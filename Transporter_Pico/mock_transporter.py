"""
mock_transporter.py
Simulates the Pico 2W Transporter for local auditor testing.

Implements the full protocol:
  UDP:
    - Receives signed beacons  (PKT_BEACON  0x01, 129 bytes) via multicast
    - Receives signed bids     (PKT_BID     0x02, 137 bytes) via unicast BID_PORT
    - Broadcasts signed anomaly (PKT_ANOMALY 0x03, 133 bytes) via multicast
    - Sends signed quorum notif (PKT_QUORUM  0x04, 129 bytes) directed unicast

  HTTP (simulates both Pico endpoints and the Flow contract in dev mode):
    GET  /data?pubkey=<hex>  → 402 + nonce
    POST /pay               → 200 with { csv, payload }
    POST /verdict           → simulates SwarmVerifierV4.submitVerdict()
    GET  /state             → dashboard snapshot

Three-phase settlement (mirrors SwarmVerifierV4.cdc):
  Phase 1 — registerAnomaly: after quorum selected, submission_sig computed,
             escrow locked (simulated), event registered in pending_events.
  Phase 2 — submitVerdict:  each auditor posts to /verdict independently.
             Mock validates fields, signature, quorum membership, no duplicates.
  Phase 3 — finalizeEvent:  triggered when all verdicts received or timeout.
             Silent auditors counted as verdict=False, confidence=0.0.
             Transporter slashed if consensus contradicts their claim.
             After finalization: simulate Storacha upload → fake CID → updateEventCid.

Bid packet: 137 bytes
  [0x02 | pubkey 64B | price float64 LE 8B | sig over bytes 0-72, 64B]

Payload object in 200 /pay response (must match what auditor.py expects):
  {
    transporter_pubkey,   auditor_pubkey,
    anomaly_confidence,   timestamp_ms,
    submission_sig,       ← eventId the contract uses (auditor reads this key)
    payload_signature,    ← per-auditor sig tying verdict to this event
  }

Verdict body POSTed by auditor.py (must match what _handle_verdict reads):
  {
    event_id,             ← submission_sig, the contract's event key
    auditor_pubkey,       ← 128 hex chars
    verdict,              ← bool
    verdict_confidence,   ← float 0.0–1.0
    payload_signature,    ← hex sig the transporter issued in the 200 response
    verdict_signature,    ← auditor's ECDSA sig over canonical string
    csv_cid,              ← always "" from auditors
  }
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
import requests
from dotenv import load_dotenv
from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
from flow_py_sdk import flow_client
from flow_py_sdk.cadence import String, UFix64, Bool, Array, Address
from flow_py_sdk.tx import Tx, ProposalKey

load_dotenv()

# ── Protocol constants (must match config.h and auditor.py) ──────────────────
MULTICAST_GROUP    = "239.0.0.1"
MULTICAST_PORT     = 5005
BID_PORT           = 5006
HTTP_PORT          = 8080

CSV_BUFFER_SAMPLES = 75
WINDOW_SIZE        = 50

BID_WINDOW_S      = 0.6    # collect bids before selecting quorum
VERDICT_TIMEOUT_S = 55.0   # wait for all quorum verdicts before force-finalizing

# Quorum scoring weights (must match QUORUM_W_* build flags in config.h)
W_PRICE = 0.5
W_REP   = 0.3
W_STAKE = 0.2
QUORUM_SIZE = 3

# Reputation formula constants (must match SwarmVerifierV4.cdc)
ALPHA = 10.0
BETA  = 5.0

# Anomaly confidence threshold (must match ANOMALY_CONFIDENCE_THRESHOLD in config.h)
ANOMALY_THRESHOLD = 0.85

# ── Flow testnet config ───────────────────────────────────────────────────────
# Set FLOW_ENABLED = True once SwarmVerifierV4 is deployed to testnet.
# When False: quorum scoring uses local bid prices only (no stake/rep lookup).
FLOW_ENABLED       = True
FLOW_REST_URL      = "https://rest-testnet.onflow.org/v1/scripts"
FLOW_CONTRACT_ADDR = "0xfcd23c8d1553708a"
FLOW_CONTRACT_NAME = "SwarmVerifierV4"
PAYMENT_PER_AUDITOR = 0.001  # FLOW paid to each aligned auditor per event


from ecdsa.util import sigencode_string
from flow_py_sdk.signer import Signer as FlowSigner

class _EcdsaSigner(FlowSigner):
    def __init__(self, sk: SigningKey):
        self._sk = sk

    def sign(self, message: bytes, tag=None) -> bytes:
        if tag is not None:
            message = tag + message
        return self._sk.sign(
            message,
            hashfunc=hashlib.sha3_256,
            sigencode=sigencode_string,
        )

# ── Crypto helpers ────────────────────────────────────────────────────────────

def _sign(sk, data: bytes) -> bytes:
    return sk.sign(data, hashfunc=hashlib.sha256)

def _verify(payload: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
        vk.verify(sig, payload, hashfunc=hashlib.sha256)
        return True
    except (BadSignatureError, Exception):
        return False


# ── Mock IMU data generator ───────────────────────────────────────────────────

def _generate_drop_csv(n_rows: int = CSV_BUFFER_SAMPLES) -> str:
    """
    Generates a CSV resembling a real drop event:
      Rows 0-37  : normal idle motion (low noise)
      Rows 38-56 : free-fall (near-zero linear acceleration)
      Rows 57-74 : impact spike
    Columns: timestamp_ms,ax,ay,az,qw,qx,qy,qz
    """
    rows = []
    t    = int(time.time() * 1000) - n_rows * 20   # 50 Hz → 20 ms/sample

    for i in range(n_rows):
        phase = i / n_rows
        if phase < 0.5:
            ax, ay, az = np.random.normal(0, 0.05, 3)
        elif phase < 0.75:
            ax, ay, az = np.random.normal(0, 0.01, 3)
        else:
            ax = np.random.normal(0,    2.0)
            ay = np.random.normal(0,    2.0)
            az = np.random.normal(-9.8, 3.0)

        qw = 1.0 + np.random.normal(0, 0.005)
        qx, qy, qz = np.random.normal(0, 0.005, 3)
        rows.append(f"{t},{ax:.6f},{ay:.6f},{az:.6f},{qw:.6f},{qx:.6f},{qy:.6f},{qz:.6f}")
        t += 20

    return "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n" + "\n".join(rows)


# ── Transporter Registration ──────────────────────────────────────────────────
def _register_transporter_on_flow():
    if not FLOW_ENABLED:
        print("[Flow] (simulated) registerNode for transporter")
        return
    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(nodeId: String, stake: UFix64) {\n"
        "    prepare(signer: auth(Storage) &Account) {}\n"
        "    execute {\n"
        "        SwarmVerifierV4.registerNode(nodeId: nodeId, stake: stake)\n"
        "    }\n"
        "}"
    )
    stake_ufix = int(10.0 * 1e8)
    def build(tx):
        tx = tx.add_arguments(String(state.pub_hex))
        tx = tx.add_arguments(UFix64(stake_ufix))
        return tx
    try:
        with _flow_tx_lock:
            asyncio.run(_flow_tx_async(cadence, build, "registerNode(transporter)", wait_seal=True))
    except Exception as e:
        if "already registered" not in str(e):
            print(f"[Flow] Transporter registerNode error: {e}")
        else:
            print("[Flow] Transporter already registered on-chain.")

# ── Shared transporter state ──────────────────────────────────────────────────

class TransporterState:
    def __init__(self):
        self.sk, self.vk = self._load_or_generate_keypair("./transporter_identity.pem")
        self.pub_bytes   = self.vk.to_string()
        self.pub_hex     = self.pub_bytes.hex()

        # Auditor registry: pubkey_hex → { ip, last_seen }
        self.registry      = {}
        self.registry_lock = threading.Lock()

        # Bid collection: pubkey_hex → { ip, price }
        self.bids          = {}
        self.bids_lock     = threading.Lock()
        self.collecting_bids = False

        # Quorum: pubkey_hex → ip (set after bid window closes)
        self.quorum = {}

        # x402 nonces: pubkey_hex → nonce_bytes (refreshed each GET /data)
        self.nonces      = {}
        self.nonces_lock = threading.Lock()

        # Per-event payload sigs: pubkey_hex → payload_sig_hex
        # Used to validate that an auditor's verdict refers to data they actually received.
        self.issued_payload_sigs      = {}
        self.issued_payload_sigs_lock = threading.Lock()

        # Current event
        # submission_sig is the unique event key used by the Flow contract
        # (submissionSig in registerAnomaly / anomalyLedger).
        # It is the ECDSA sig over the canonical payload — computed after quorum
        # selection and stored here so we can serve it in the /pay payload and
        # validate it in /verdict bodies from auditors.
        self.current_event_id:   str   = ""   # submission_sig hex
        self.anomaly_confidence: float = 0.93
        self.csv_data:           str   = ""

        # Pending verdicts for the current event: pubkey_hex → verdict dict
        self.verdicts      = {}
        self.verdicts_lock = threading.Lock()
        self.expected_verdicts = 0

        # Set when registerAnomaly TX is sealed on Flow — gates POST /pay
        # so auditors cannot fetch data before the pendingEvent exists on-chain.
        self.register_sealed = threading.Event()
        self.register_sealed.set()  # pre-set so FLOW_ENABLED=False path is unblocked

        # Dashboard
        self.system_status  = "IDLE"   # IDLE | ANOMALY | DELIVERING
        self.settled_events = []        # last 20 finalized events
        self.events_lock    = threading.Lock()
        self.last_quat      = {"qw": 1.0, "qx": 0.0, "qy": 0.0, "qz": 0.0}

        print(f"[Transporter] pubkey={self.pub_hex[:16]}...")

    @staticmethod
    def _load_or_generate_keypair(key_path: str):
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                sk = SigningKey.from_pem(f.read())
            print(f"[Transporter] Loaded existing identity from {key_path}")
        else:
            sk = SigningKey.generate(curve=NIST256p)
            with open(key_path, "wb") as f:
                f.write(sk.to_pem())
            print(f"[Transporter] Generated new identity, saved to {key_path}")
        return sk, sk.verifying_key
    
    # ── Packet builders ───────────────────────────────────────────────────────

    def build_anomaly_packet(self) -> bytes:
        """
        PKT_ANOMALY (0x03, 133 bytes):
          byte  0     : 0x03
          bytes 1-64  : transporter pubkey
          bytes 65-68 : confidence float32 LE
          bytes 69-132: ECDSA sig over bytes 0-68
        """
        header     = struct.pack('<B', 0x03)
        conf_bytes = struct.pack('<f', self.anomaly_confidence)
        to_sign    = header + self.pub_bytes + conf_bytes
        sig        = _sign(self.sk, to_sign)
        packet     = to_sign + sig
        assert len(packet) == 133
        return packet

    def build_quorum_packet(self, auditor_pubkey_bytes: bytes) -> bytes:
        """
        PKT_QUORUM (0x04, 129 bytes):
          byte  0     : 0x04
          bytes 1-64  : nominated auditor pubkey
          bytes 65-128: ECDSA sig over bytes 0-64, signed by TRANSPORTER

        The auditor verifies:
          1. Sig is valid using the transporter pubkey (known from PKT_ANOMALY)
          2. bytes 1-64 == own pubkey
        """
        header = struct.pack('<B', 0x04) + auditor_pubkey_bytes   # 65 bytes
        sig    = _sign(self.sk, header)
        packet = header + sig
        assert len(packet) == 129
        return packet

    def build_submission_sig(self, quorum_ids: list) -> str:
        """
        Computes the submission_sig that acts as the unique event ID on the
        Flow contract (the 'submissionSig' / eventId in registerAnomaly and
        anomalyLedger). Signs: transporter_pubkey + anomaly_confidence +
        timestamp + sorted quorum pubkeys.
        """
        canonical = json.dumps({
            "transporter_pubkey": self.pub_hex,
            "anomaly_confidence": self.anomaly_confidence,
            "timestamp_ms":       int(time.time() * 1000),
            "quorum_ids":         sorted(quorum_ids),
        }, separators=(',', ':')).encode()
        return _sign(self.sk, canonical).hex()

    def build_payload_json(self, auditor_pubkey_hex: str) -> dict:
        timestamp_ms = int(time.time() * 1000)
        
        # 1. Manually build the canonical string to strictly match Pico C++ format
        canonical_str = (
            f'{{"anomaly_confidence":{self.anomaly_confidence:.4f},'
            f'"auditor_pubkey":"{auditor_pubkey_hex}",'
            f'"event_id":"{self.current_event_id}",'
            f'"timestamp_ms":{timestamp_ms},'
            f'"transporter_pubkey":"{self.pub_hex}"}}'
        )
        sig_hex = _sign(self.sk, canonical_str.encode('utf-8')).hex()

        # 2. Build the output body
        body = {
            "transporter_pubkey":  self.pub_hex,
            "auditor_pubkey":      auditor_pubkey_hex,
            "anomaly_confidence":  self.anomaly_confidence,
            "timestamp_ms":        timestamp_ms,
            "event_id":            self.current_event_id,
            "payload_signature":   sig_hex,
            "deposit":             0.5
        }

        with self.issued_payload_sigs_lock:
            self.issued_payload_sigs[auditor_pubkey_hex] = sig_hex

        return body

state = TransporterState()


# ── HTTP handler ──────────────────────────────────────────────────────────────

class TransporterHTTP(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass   # suppress default Apache-style logs

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass  # client disconnected, nothing to do

    def do_GET(self):
        parsed    = urlparse(self.path)
        client_ip = self.client_address[0]

        if parsed.path == "/state":
            self._handle_state()
            return
        if parsed.path == "/data":
            params     = parse_qs(parsed.query)
            pubkey_hex = params.get("pubkey", [None])[0]
            self._handle_data(pubkey_hex, client_ip)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/pay":
            self._handle_pay(body)
        elif self.path == "/verdict":
            # Simulates SwarmVerifierV4.submitVerdict() in dev mode.
            # When FLOW_ENABLED=True, auditors post directly to the contract
            # and this endpoint is unused.
            self._handle_verdict(body)
        else:
            self._send_json(404, {"error": "not found"})

    # ── GET /state ────────────────────────────────────────────────────────────

    def _handle_state(self):
        with state.registry_lock:
            registry = {
                pub: {
                    "ip":        info["ip"],
                    "last_seen": info["last_seen"],
                    "active":    (time.time() - info["last_seen"]) < 15,
                }
                for pub, info in state.registry.items()
            }

        with state.bids_lock:
            quorum = list(state.quorum.keys())

        with state.verdicts_lock:
            verdicts = {
                pub: {
                    "verdict":    v["verdict"],
                    "confidence": v["confidence"],
                    "ip":         v["ip"],
                    "aligned":    v.get("aligned"),
                }
                for pub, v in state.verdicts.items()
            }

        with state.events_lock:
            events = list(state.settled_events)

        self._send_json(200, {
            "transporter_pubkey":  state.pub_hex,
            "system_status":       state.system_status,
            "anomaly_confidence":  state.anomaly_confidence,
            "current_event_id":    state.current_event_id,
            "registry":            registry,
            "quorum":              quorum,
            "verdicts":            verdicts,
            "last_quat":           state.last_quat,
            "settled_events":      events,
            "ts":                  time.time(),
        })

    # ── GET /data ─────────────────────────────────────────────────────────────

    def _handle_data(self, pubkey_hex, client_ip):
        if not pubkey_hex or len(pubkey_hex) != 128:
            self._send_json(400, {"error": "missing or invalid ?pubkey query param"})
            return

        if not state.quorum:
            self._send_json(403, {"error": "no active quorum"})
            return

        if pubkey_hex not in state.quorum:
            print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... → 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        nonce = secrets.token_bytes(16)
        with state.nonces_lock:
            state.nonces[pubkey_hex] = nonce

        print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... → 402 nonce={nonce.hex()[:12]}...")
        self._send_json(402, {
            "status":      "payment_required",
            "endpoint":    "/pay",
            "nonce":       nonce.hex(),
            "description": "Sign the nonce with your private key to receive IMU data",
        })

    # ── POST /pay ─────────────────────────────────────────────────────────────

    def _handle_pay(self, body: dict):
        client_ip  = self.client_address[0]
        pubkey_hex = body.get("pubkey", "")
        sig_hex    = body.get("signature", "")

        if len(pubkey_hex) != 128 or len(sig_hex) != 128:
            self._send_json(400, {"error": "pubkey and signature must be 128 hex chars each"})
            return

        with state.nonces_lock:
            nonce = state.nonces.get(pubkey_hex)

        if not nonce:
            self._send_json(403, {"error": "no pending nonce for this pubkey — call GET /data first"})
            return

        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(nonce, sig_bytes, pub_bytes):
            print(f"[HTTP] POST /pay {client_ip} → 403 bad signature")
            self._send_json(403, {"error": "signature verification failed"})
            return

        if pubkey_hex not in state.quorum:
            print(f"[HTTP] POST /pay {client_ip} → 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        # Block until registerAnomaly is sealed on-chain (pendingEvent must exist
        # before auditors submit verdicts). Timeout matches DELIVERY_WAIT_S on auditor.
        if not state.register_sealed.wait(timeout=55):
            print(f"[HTTP] POST /pay {client_ip} → 503 registerAnomaly seal timeout")
            self._send_json(503, {"error": "chain not ready — try again"})
            return

        # Invalidate nonce immediately — prevents replay
        with state.nonces_lock:
            state.nonces.pop(pubkey_hex, None)

        if not _submit_deposit_on_flow(state.current_event_id, pubkey_hex):
            print(f"[HTTP] POST /pay {client_ip} → 503 recordDeposit failed")
            self._send_json(503, {"error": "Flow.recordDeposit() failed — deposit not locked on-chain"})
            return

        print(f"[HTTP] POST /pay {client_ip} pubkey={pubkey_hex[:12]}... → 200 OK")
        payload = state.build_payload_json(pubkey_hex)
        self._send_json(200, {
            "csv":     state.csv_data,
            "payload": payload,
        })

    # ── POST /verdict  (simulates SwarmVerifierV4.submitVerdict) ─────────────

    def _handle_verdict(self, body: dict):
        """
        Simulates the Flow contract's submitVerdict() function.

        Expected fields (must match auditor._submit_verdict body):
          event_id            — submission_sig hex (the contract's event key)
          auditor_pubkey      — 128 hex chars
          verdict             — bool
          verdict_confidence  — float 0.0–1.0
          payload_signature   — hex sig the transporter issued in the 200 response
          verdict_signature   — auditor's ECDSA sig over canonical string
          csv_cid             — always "" from auditors
        """
        client_ip = self.client_address[0]

        event_id          = body.get("event_id",           "")
        auditor_pub       = body.get("auditor_pubkey",     "")
        verdict           = body.get("verdict")
        confidence        = body.get("verdict_confidence")
        payload_sig_hex   = body.get("payload_signature",  "")
        verdict_sig_hex   = body.get("verdict_signature",  "")
        csv_cid           = body.get("csv_cid",            "")   # accepted but always ""

        # ── Field presence check
        missing = [f for f, v in [
            ("event_id",          event_id),
            ("auditor_pubkey",    auditor_pub),
            ("verdict",          verdict),
            ("verdict_confidence", confidence),
            ("payload_signature", payload_sig_hex),
            ("verdict_signature", verdict_sig_hex),
        ] if v is None or v == ""]
        if missing:
            self._send_json(400, {"error": f"missing fields: {missing}"})
            return

        # ── event_id must match the current active event
        if event_id != state.current_event_id:
            print(f"[Verdict] {client_ip} event_id mismatch: got {event_id[:16]}... "
                  f"expected {state.current_event_id[:16]}...")
            self._send_json(409, {"error": "event_id does not match active event"})
            return

        # ── Quorum membership
        if auditor_pub not in state.quorum:
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 not in quorum")
            self._send_json(403, {"error": "not in quorum"})
            return

        # ── Duplicate check
        with state.verdicts_lock:
            if auditor_pub in state.verdicts:
                self._send_json(409, {"error": "verdict already received from this auditor"})
                return

        # ── Verify payload_signature matches what we issued to this auditor
        with state.issued_payload_sigs_lock:
            expected_payload_sig = state.issued_payload_sigs.get(auditor_pub, "")
        if payload_sig_hex != expected_payload_sig:
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 payload_sig mismatch")
            self._send_json(403, {"error": "payload_signature does not match issued value"})
            return

        # ── Verify verdict signature
        # Canonical: "<128-hex-pubkey>:<0 or 1>:<confidence:.4f>"
        # int() cast is mandatory — bool True → 'True', int(True) → '1'
        canonical = f"{auditor_pub}:{int(verdict)}:{float(confidence):.4f}".encode()
        try:
            pub_bytes = bytes.fromhex(auditor_pub)
            sig_bytes = bytes.fromhex(verdict_sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(canonical, sig_bytes, pub_bytes):
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 bad verdict sig")
            self._send_json(403, {"error": "verdict signature verification failed"})
            return

        with state.verdicts_lock:
            state.verdicts[auditor_pub] = {
                "verdict":           bool(verdict),
                "confidence":        float(confidence),
                "payload_signature": payload_sig_hex,
                "verdict_signature": verdict_sig_hex,
                "csv_cid":           csv_cid,
                "ip":                client_ip,
            }
            count = len(state.verdicts)

        label = "DROP" if verdict else "NORMAL"
        print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → {label} "
              f"conf={float(confidence):.4f} ({count}/{state.expected_verdicts})")
        self._send_json(200, {"status": "received"})

        if count >= state.expected_verdicts:
            threading.Thread(target=_finalize_event, daemon=True).start()


# ── Consensus / finalization  (mirrors SwarmVerifierV4.finalizeEvent) ─────────

def _finalize_event():
    """
    Phase 3: compute Cswarm, majority verdict, reputation deltas, transporter
    slash. Then simulate Storacha upload and updateEventCid.

    Silent auditors (in quorum but no verdict received) are treated as
    verdict=False, confidence=0.0 — identical penalty to wrong verdict.
    This closes the free-rider attack: an auditor cannot observe others'
    verdicts and submit last to guarantee alignment. Silence = wrong answer.
    """
    saved_event_id = state.current_event_id
    with state.verdicts_lock:
        received = dict(state.verdicts)

    quorum_ids = list(state.quorum.keys())
    n          = len(quorum_ids)

    if n == 0:
        return

    # ── Build full verdict set including silent auditors ─────────────────────
    all_verdicts = {}
    for pub in quorum_ids:
        if pub in received:
            all_verdicts[pub] = received[pub]
        else:
            # Silent — penalised same as wrong verdict
            all_verdicts[pub] = {
                "verdict":    False,
                "confidence": 0.0,
                "ip":         state.quorum.get(pub, "?"),
                "silent":     True,
            }

    # ── Cswarm and majority vote ──────────────────────────────────────────────
    confidences       = [v["confidence"] for v in all_verdicts.values()]
    drop_votes        = sum(1 for v in all_verdicts.values() if v["verdict"])
    cswarm            = sum(confidences) / n
    consensus_verdict = drop_votes > (n // 2)

    # ── Per-auditor reputation delta and alignment ────────────────────────────
    auditor_results = []
    for pub in quorum_ids:
        v       = all_verdicts[pub]
        aligned = (v["verdict"] == consensus_verdict) and not v.get("silent", False)
        delta   = ALPHA * (cswarm - v["confidence"]) - (BETA if not aligned else 0.0)
        auditor_results.append({
            "pubkey_hex": pub,
            "ip":         v.get("ip", "?"),
            "verdict":    v["verdict"],
            "confidence": v["confidence"],
            "aligned":    aligned,
            "silent":     v.get("silent", False),
            "delta":      round(delta, 4),
        })

    # Update alignment flags in live verdicts dict (dashboard reads these)
    with state.verdicts_lock:
        for r in auditor_results:
            if r["pubkey_hex"] in state.verdicts:
                state.verdicts[r["pubkey_hex"]]["aligned"] = r["aligned"]

    # ── Transporter slashing ──────────────────────────────────────────────────
    # Transporter claimed a drop (confidence >= threshold).
    # If consensus disagrees, transporter is slashed.
    transporter_claimed_drop = state.anomaly_confidence >= ANOMALY_THRESHOLD
    transporter_slashed      = transporter_claimed_drop != consensus_verdict

    # ── Print settlement summary ──────────────────────────────────────────────
    print("\n" + "═" * 64)
    print(f"  SETTLEMENT — event_id={saved_event_id[:16]}...")
    print("═" * 64)
    print(f"  Auditors     : {n}  (received: {len(received)}  silent: {n - len(received)})")
    print(f"  Drop votes   : {drop_votes}/{n}")
    print(f"  Cswarm       : {cswarm:.4f}")
    print(f"  Consensus    : {'DROP CONFIRMED' if consensus_verdict else 'NORMAL — false positive'}")
    print(f"  Transporter  : conf={state.anomaly_confidence:.4f}  "
          f"claimed_drop={transporter_claimed_drop}  "
          f"slashed={transporter_slashed}")
    print("─" * 64)
    for r in auditor_results:
        status  = "✓ aligned" if r["aligned"] else ("✗ silent" if r["silent"] else "✗ deviated")
        verdict = "DROP" if r["verdict"] else "NORM"
        print(f"  {r['pubkey_hex'][:12]}...  {verdict}  conf={r['confidence']:.4f}  "
              f"ΔR={r['delta']:+.4f}  {status}")
    print("═" * 64)

    # ── Phase 3: finalizeEvent on Flow ───────────────────────────────────────
    saved_event_id = state.current_event_id
    if FLOW_ENABLED and saved_event_id:
        print("[Flow] Calling finalizeEvent on-chain...")
        threading.Thread(target=_finalize_event_on_flow,
                         args=(saved_event_id,), daemon=True).start()

    # ── Simulate post-consensus Storacha upload ───────────────────────────────
    print("[Storacha] Simulating post-consensus bundle upload...")
    time.sleep(0.3)   # simulate upload latency
    cid = "bafyrei" + secrets.token_hex(16)
    print(f"[Storacha] CID={cid}")

    # ===== NEW ON-CHAIN CALL =====
    if FLOW_ENABLED and saved_event_id:
        print("[Flow] Calling updateEventCid on-chain...")
        threading.Thread(target=_update_cid_on_flow,
                         args=(saved_event_id, cid), daemon=True).start()
        flow_tx = "submitted" # Actual tx hash will be printed by the async tx runner
    else:
        flow_tx = "0x" + secrets.token_hex(8)
        print(f"[Flow] (simulated) updateEventCid → tx={flow_tx}")
    # =============================
    
    print("═" * 64 + "\n")

    # ── Store finalized event for /state dashboard ────────────────────────────
    event = {
        "event_id":            state.current_event_id,
        "timestamp":           time.time(),
        "anomaly_confidence":  state.anomaly_confidence,
        "cswarm":              round(cswarm, 4),
        "consensus_verdict":   consensus_verdict,
        "drop_votes":          drop_votes,
        "total_auditors":      n,
        "transporter_slashed": transporter_slashed,
        "auditor_results":     auditor_results,
        "storacha_cid":        cid,
        "flow_tx":             flow_tx,
    }
    with state.events_lock:
        state.settled_events.insert(0, event)
        state.settled_events = state.settled_events[:20]

    state.system_status = "IDLE"


# ── UDP listeners ─────────────────────────────────────────────────────────────

def multicast_listener():
    """Receives signed beacons (PKT_BEACON 0x01, 129 bytes) via multicast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', MULTICAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f"[UDP] Multicast listener on {MULTICAST_GROUP}:{MULTICAST_PORT}")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 129 and data[0] == 0x01:
            _handle_beacon(data, addr)


def bid_listener():
    """
    Receives signed bids (PKT_BID 0x02, 137 bytes) via unicast on BID_PORT.

    Bid format (137 bytes):
      byte  0     : 0x02
      bytes 1-64  : auditor pubkey
      bytes 65-72 : bid price float64 LE
      bytes 73-136: ECDSA sig over bytes 0-72
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', BID_PORT))
    print(f"[UDP] Bid listener on 0.0.0.0:{BID_PORT}")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 137 and data[0] == 0x02:
            _handle_bid(data, addr)


def _handle_beacon(data: bytes, addr):
    pub_bytes     = data[1:65]
    sig           = data[65:129]
    signed_region = data[0:65]

    if not _verify(signed_region, sig, pub_bytes):
        print(f"[UDP] Beacon from {addr[0]} — bad signature, dropping")
        return

    pub_hex = pub_bytes.hex()
    with state.registry_lock:
        is_new = pub_hex not in state.registry
        state.registry[pub_hex] = {"ip": addr[0], "last_seen": time.time()}

    if is_new:
        print(f"[UDP] ✓ Registered  {addr[0]}  pubkey={pub_hex[:12]}...")
    else:
        print(f"[UDP] ↻ Refreshed   {addr[0]}  pubkey={pub_hex[:12]}...")


def _handle_bid(data: bytes, addr):
    if not state.collecting_bids:
        return

    pub_bytes     = data[1:65]
    price_bytes   = data[65:73]
    sig           = data[73:137]
    signed_region = data[0:73]   # sig covers type + pubkey + price

    if not _verify(signed_region, sig, pub_bytes):
        print(f"[UDP] Bid from {addr[0]} — bad signature, dropping")
        return

    pub_hex = pub_bytes.hex()
    price   = struct.unpack('<d', price_bytes)[0]

    # Must have registered via beacon first
    with state.registry_lock:
        if pub_hex not in state.registry:
            print(f"[UDP] Bid from unregistered pubkey {pub_hex[:12]}... — dropping")
            return

    with state.bids_lock:
        if pub_hex in state.bids:
            return   # duplicate bid from same auditor
        state.bids[pub_hex] = {"ip": addr[0], "price": price}

    print(f"[UDP] ✓ Bid from {addr[0]}  pubkey={pub_hex[:12]}...  price={price:.4f} FLOW")


# ── Flow stake/reputation query ───────────────────────────────────────────────

def _decode_cadence(v):
    """Recursively decode a Cadence JSON value to a Python primitive."""
    if v is None:
        return None
    t = v.get("type") if isinstance(v, dict) else None
    if t in ("String",):
        return v["value"]
    if t in ("Fix64", "UFix64"):
        return float(v["value"])
    if t in ("Int", "UInt", "Int8", "UInt8", "Int16", "UInt16",
             "Int32", "UInt32", "Int64", "UInt64"):
        return int(v["value"])
    if t == "Bool":
        return v["value"]
    if t == "Array":
        return [_decode_cadence(i) for i in (v.get("value") or [])]
    if t == "Optional":
        return _decode_cadence(v["value"]) if v.get("value") is not None else None
    # fallback — return raw value field
    return v.get("value") if isinstance(v, dict) else v


def _query_flow_stake_reputation(pubkey_hex: str) -> tuple:
    """
    Query SwarmVerifierV4 on Flow testnet for stake and reputation.
    Returns (stake: float, reputation: float). Falls back to (0.0, 0.0) on error.

    Two separate queries avoid the UFix64→Fix64 cast that Cadence 1.0 rejects.
    """
    if not FLOW_ENABLED:
        return (0.0, 0.0)

    # Return stake (UFix64?) and reputation (Fix64?) as separate Optional values
    # wrapped in a struct-like Array so one script call fetches both.
    # UFix64 and Fix64 cannot be mixed in a single typed array — use AnyStruct.
    script = f"""
import {FLOW_CONTRACT_NAME} from {FLOW_CONTRACT_ADDR}
access(all) fun main(pubkey: String): [AnyStruct] {{
    let stake: UFix64? = {FLOW_CONTRACT_NAME}.getStake(nodeId: pubkey)
    let rep: Fix64?   = {FLOW_CONTRACT_NAME}.getReputation(nodeId: pubkey)
    let stakeVal: UFix64 = stake ?? 0.0
    let repVal: Fix64    = rep   ?? 0.0
    return [stakeVal, repVal]
}}
""".strip()

    encoded_script = base64.b64encode(script.encode()).decode()
    encoded_arg    = base64.b64encode(
        json.dumps({"type": "String", "value": pubkey_hex}).encode()
    ).decode()

    try:
        resp = requests.post(
            FLOW_REST_URL,
            json={"script": encoded_script, "arguments": [encoded_arg]},
            timeout=5,
        )
        if resp.status_code != 200:
            try:
                err = resp.json()
                print(f"[Flow] Script query failed {resp.status_code}: {err.get('message', resp.text[:120])}")
            except Exception:
                print(f"[Flow] Script query failed {resp.status_code}: {resp.text[:120]}")
            return (0.0, 0.0)

        # Response: {"value": "<base64-encoded Cadence JSON>"}
        raw_b64 = resp.json()
        if isinstance(raw_b64, dict):
            raw_b64 = raw_b64.get("value", "")
        decoded_bytes = base64.b64decode(raw_b64)
        cadence_val   = json.loads(decoded_bytes)
        values        = _decode_cadence(cadence_val)   # should be [stake, rep]

        if not isinstance(values, list) or len(values) < 2:
            print(f"[Flow] Unexpected script result shape: {cadence_val!r}")
            return (0.0, 0.0)

        stake = float(values[0]) if values[0] is not None else 0.0
        rep   = float(values[1]) if values[1] is not None else 0.0
        return (stake, rep)

    except Exception as e:
        print(f"[Flow] Query error for {pubkey_hex[:12]}...: {e}")
        return (0.0, 0.0)


# ── Quorum selection ──────────────────────────────────────────────────────────

def _select_quorum(bids: dict) -> dict:
    """
    Rank bidding auditors by weighted score:
      score = W_PRICE*(1/price) + W_REP*reputation + W_STAKE*stake

    When FLOW_ENABLED=False, stake and reputation are both 0.0 so ranking
    is purely by bid price (cheapest wins).

    Returns dict pubkey_hex → { ip, price, stake, reputation, score }
    for the top QUORUM_SIZE bidders.
    """
    if not bids:
        return {}

    print(f"[Quorum] Scoring {len(bids)} bidder(s)...")
    scored = []
    for pub_hex, bid in bids.items():
        stake, rep = _query_flow_stake_reputation(pub_hex)
        price = bid["price"]
        if price <= 0.0:
            print(f"[Quorum]   {pub_hex[:12]}... price={price} — skipping (invalid price)")
            continue
        score = W_PRICE * (1.0 / price) + W_REP * rep + W_STAKE * stake
        scored.append({
            "pubkey_hex": pub_hex,
            "ip":         bid["ip"],
            "price":      price,
            "stake":      stake,
            "reputation": rep,
            "score":      score,
        })
        print(f"[Quorum]   {pub_hex[:12]}...  price={price:.4f}  stake={stake:.2f}  "
              f"rep={rep:.4f}  score={score:.4f}")

    scored.sort(key=lambda x: x["score"], reverse=True)
    top = scored[:QUORUM_SIZE]
    return {e["pubkey_hex"]: e["ip"] for e in top}


# ── PKT_QUORUM sender ─────────────────────────────────────────────────────────

def _send_quorum_notifications(quorum: dict):
    """
    Send PKT_QUORUM (0x04, 129 bytes) to the MULTICAST group (not unicast).

    Unicast + SO_REUSEPORT only delivers to ONE socket when multiple auditor
    processes share the same IP (Linux load-balances unicast across SO_REUSEPORT
    sockets). Multicast delivers to ALL of them. Each auditor's _handle_quorum
    already checks bytes 1-64 == own pubkey and discards packets not for them,
    so broadcasting to the group is functionally identical but works correctly
    with multiple auditors on the same machine.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    for pub_hex, ip in quorum.items():
        try:
            pub_bytes = bytes.fromhex(pub_hex)
        except ValueError:
            print(f"[Quorum] Cannot decode pubkey for {ip} — skipping")
            continue
        packet = state.build_quorum_packet(pub_bytes)
        sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
        print(f"[Quorum] Sent PKT_QUORUM → multicast (for pubkey={pub_hex[:12]}...)")
    sock.close()


# ── Anomaly trigger ────────────────────────────────────────────────────────────

def trigger_anomaly():
    """
    Full anomaly event cycle:
      1. Generate CSV + set confidence
      2. Broadcast PKT_ANOMALY
      3. Collect bids for BID_WINDOW_S
      4. Score bids → select quorum
      5. Compute submission_sig (event ID for Flow contract)
      6. Phase 1: registerAnomaly (simulated)
      7. Send PKT_QUORUM to each selected auditor
      8. Arm HTTP server for x402 delivery
      9. Wait VERDICT_TIMEOUT_S for all verdicts
     10. Force-finalize after timeout with whatever verdicts arrived
    """
    # ── Prepare event data
    state.csv_data           = _generate_drop_csv()
    state.anomaly_confidence = round(float(np.random.uniform(0.87, 0.99)), 4)

    try:
        last_row = state.csv_data.strip().split("\n")[-1].split(",")
        state.last_quat = {
            "qw": float(last_row[4]), "qx": float(last_row[5]),
            "qy": float(last_row[6]), "qz": float(last_row[7]),
        }
    except Exception:
        pass

    # Reset per-event state
    with state.bids_lock:
        state.bids.clear()
    with state.verdicts_lock:
        state.verdicts.clear()
    with state.issued_payload_sigs_lock:
        state.issued_payload_sigs.clear()
    state.quorum.clear()
    state.current_event_id = ""
    state.collecting_bids  = True
    state.system_status    = "ANOMALY"
    state.register_sealed.clear()   # will be re-set once TX seals (or on error)

    # ── Broadcast PKT_ANOMALY
    packet = state.build_anomaly_packet()
    sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
    sock.close()
    print(f"\n[Anomaly] Broadcast PKT_ANOMALY | confidence={state.anomaly_confidence:.4f}")
    print(f"[Anomaly] Collecting bids for {BID_WINDOW_S}s...")

    # ── Collect bids
    time.sleep(BID_WINDOW_S)
    state.collecting_bids = False

    with state.bids_lock:
        all_bids = dict(state.bids)

    if not all_bids:
        print("[Anomaly] No bids received — returning to IDLE\n")
        state.system_status = "IDLE"
        return

    # ── Score bids and select quorum
    quorum = _select_quorum(all_bids)

    if not quorum:
        print("[Anomaly] No eligible quorum members — returning to IDLE\n")
        state.system_status = "IDLE"
        return

    state.quorum            = quorum
    state.expected_verdicts = len(quorum)

    # ── Compute submission_sig — the unique event ID for the Flow contract.
    # This is built from the transporter pubkey, confidence, timestamp, and
    # sorted quorum pubkeys, then ECDSA-signed. The contract stores all events
    # under this key in anomalyLedger and pendingEvents.
    state.current_event_id = state.build_submission_sig(list(quorum.keys()))

    src = "Flow-ranked" if FLOW_ENABLED else "local (bid price only)"
    print(f"[Anomaly] Quorum ({src}): {len(quorum)} auditor(s)")
    for pub_hex, ip in quorum.items():
        bid = all_bids.get(pub_hex, {})
        print(f"           {ip}  pubkey={pub_hex[:12]}...  price={bid.get('price', '?'):.4f} FLOW")
    print(f"[Anomaly] submission_sig (event_id)={state.current_event_id[:24]}...")

    # ── Clear seal gate BEFORE sending PKT_QUORUM.
    # Auditors will block at POST /pay until registerAnomaly is sealed.
    state.register_sealed.clear()

    # ── Phase 1: registerAnomaly on Flow (async — seals in background).
    # Runs in a thread so PKT_QUORUM goes out immediately.
    # The /pay gate (register_sealed.wait) holds auditors until sealed.
    register_thread = threading.Thread(
        target=_register_anomaly_on_flow, args=(quorum,), daemon=True
    )
    register_thread.start()

    # ── Send PKT_QUORUM immediately — auditors can GET /data right away.
    # POST /pay is gated on register_sealed so they wait at the right point.
    _send_quorum_notifications(quorum)

        # NEW
    state.system_status = "DELIVERING"
    print(f"[Anomaly] HTTP server armed. Waiting up to {VERDICT_TIMEOUT_S}s for verdicts...")

    if FLOW_ENABLED:
        saved_event_id = state.current_event_id

        # Wait for registerAnomaly to seal before starting the verdict window.
        # Auditors are already blocked at POST /pay on register_sealed — once
        # that fires, the contract's verdictTimeoutSecs clock starts ticking.
        print("[Flow] Waiting for registerAnomaly to seal before starting verdict window...")
        state.register_sealed.wait(timeout=60)

        print(f"[Flow] registerAnomaly sealed. Waiting {VERDICT_TIMEOUT_S}s verdict window...")
        deadline = time.time() + VERDICT_TIMEOUT_S

        # Poll until all verdicts arrive or deadline
        while time.time() < deadline:
            # Check on-chain pending event for verdict count
            with state.verdicts_lock:
                received = len(state.verdicts)
            if received >= state.expected_verdicts:
                print(f"[Flow] All {received} verdicts received early — proceeding to finalize")
                break
            time.sleep(1)
        else:
            with state.verdicts_lock:
                received = len(state.verdicts)
            print(f"[Flow] Verdict window elapsed — {received}/{state.expected_verdicts} received")

        # Wait an extra buffer for auditor Flow txs to seal on-chain.
        # Contract verdictTimeoutSecs=60, our window is VERDICT_TIMEOUT_S=30 —
        # but contract clock starts when registerAnomaly seals, same as us now.
        # Add 20s buffer for block propagation lag.
        print("[Flow] Waiting 20s for auditor txs to seal on-chain...")
        time.sleep(20)

        if saved_event_id:
            print("[Flow] Calling finalizeEvent on-chain...")
            state.system_status = "FINALIZING"
            _finalize_event_on_flow(saved_event_id)  # call directly, not in thread

        state.system_status = "IDLE"
    else:
        # Mock mode — auditors POST to /verdict, _handle_verdict drives finalization.
        deadline = time.time() + VERDICT_TIMEOUT_S
        while time.time() < deadline:
            with state.verdicts_lock:
                if len(state.verdicts) >= state.expected_verdicts:
                    break
            time.sleep(0.5)
        else:
            with state.verdicts_lock:
                received = len(state.verdicts)
            print(f"[Anomaly] Verdict timeout — {received}/{state.expected_verdicts} received")
        _finalize_event()

    # ── Reset HTTP state (nonces, quorum) for next cycle
    state.quorum.clear()
    with state.nonces_lock:
        state.nonces.clear()
    print("[Anomaly] Cycle complete, returning to IDLE\n")

def _submit_deposit_on_flow(event_id: str, auditor_pub_hex: str) -> bool:
    """Phase 1.5: recordDeposit on Flow. Blocks until sealed."""
    if not FLOW_ENABLED:
        print(f"[Flow] (simulated) recordDeposit(event_id={event_id[:16]}... auditor={auditor_pub_hex[:12]}...)")
        return True

    # Uses Python implicit string concatenation to avoid f-string curly brace escaping issues
    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String, auditorId: String) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute {\n"
        "        SwarmVerifierV4.recordDeposit(eventId: eventId, auditorId: auditorId)\n"
        "    }\n"
        "}"
    )

    def build(tx):
        tx = tx.add_arguments(String(event_id))
        tx = tx.add_arguments(String(auditor_pub_hex))
        return tx

    try:
        with _flow_tx_lock:
            # wait_seal=True is critical here to ensure deposit is locked before CSV is served
            tx_id = asyncio.run(_flow_tx_async(cadence, build, "recordDeposit", wait_seal=True))
            return tx_id is not None
    except Exception as e:
        print(f"[Flow] recordDeposit error: {e}")
        return False
    
def _update_cid_on_flow(event_id: str, cid: str):
    if not FLOW_ENABLED:
        return

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String, cid: String) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute { SwarmVerifierV4.updateEventCid(eventId: eventId, cid: cid) }\n"
        "}"
    )

    def build(tx):
        tx = tx.add_arguments(String(event_id))
        tx = tx.add_arguments(String(cid))
        return tx

    try:
        with _flow_tx_lock:
            # fire-and-forget (wait_seal=False) matches Pico's implementation
            asyncio.run(_flow_tx_async(cadence, build, "updateEventCid", wait_seal=False))
    except Exception as e:
        print(f"[Flow] updateEventCid error: {e}")

_flow_tx_lock = threading.Lock()

async def _flow_tx_async(script, build_args_fn, label, wait_seal=False):
    flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "").removeprefix("0x")
    flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "").removeprefix("0x")
    if not flow_addr or not flow_key:
        print(f"[Flow] FLOW_ACCOUNT_ADDR/FLOW_ACCOUNT_KEY not set — {label} skipped")
        return None


    for attempt in range(3):
        try:
            async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                account      = await client.get_account(address=Address.from_hex(flow_addr))
                account_key  = account.keys[0]
                latest_block = await client.get_latest_block(is_sealed=True)
                tx = Tx(code=script)
                tx = build_args_fn(tx)
                tx = (tx
                    .with_reference_block_id(latest_block.id)
                    .with_gas_limit(9999)
                    .with_proposal_key(ProposalKey(
                        key_address         = Address.from_hex(flow_addr),
                        key_id              = account_key.index,
                        key_sequence_number = account_key.sequence_number,
                    ))
                    .with_payer(Address.from_hex(flow_addr))
                )
                tx.add_authorizers(Address.from_hex(flow_addr))
                sk     = SigningKey.from_string(bytes.fromhex(flow_key), curve=NIST256p)
                signer = _EcdsaSigner(sk)
                tx = tx.with_envelope_signature(
                    Address.from_hex(flow_addr),
                    account_key.index,
                    signer,
                )
                timeout = 60.0 if wait_seal else 30.0
                result  = await client.execute_transaction(tx, wait_for_seal=wait_seal, timeout=timeout)
                tx_id   = result.id.hex() if hasattr(result.id, "hex") else str(result.id)
                print(f"[Flow] ✓ {label} submitted → TX {tx_id}")
                print(f"[Flow]   https://testnet.flowscan.io/tx/{tx_id}")
                if wait_seal:
                    print(f"[Flow] ✓ {label} sealed")
                state.register_sealed.set()
                return tx_id
        except Exception as e:
            err = str(e)
            if "sequence number" in err and attempt < 2:
                print(f"[Flow] Sequence number mismatch on attempt {attempt + 1}, retrying...")
                await asyncio.sleep(2)
                continue
            if "already registered" in err:
                print(f"[Flow] {label} — already registered on-chain, skipping.")
                state.register_sealed.set()
                return None
            print(f"[Flow] {label} error: {e}")
            state.register_sealed.set()
            return None

def _register_anomaly_on_flow(quorum: dict):
    """Phase 1: registerAnomaly via Gateway. Blocks until sealed so
    pendingEvent exists on-chain before PKT_QUORUM goes to auditors."""
    if not FLOW_ENABLED:
        print(f"[Flow] (simulated) registerAnomaly("
              f"submission_sig={state.current_event_id[:16]}...  "
              f"quorum={len(quorum)}  "
              f"conf={state.anomaly_confidence:.4f})")
        return

    cadence = (
    f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
    "transaction(\n"
    "    transporterId: String, submissionSig: String,\n"
    "    anomalyConfidence: UFix64, quorumIds: [String], bidPrices: [UFix64]\n"
    ") {\n"
    "    prepare(signer: &Account) {}\n"
    "    execute {\n"
    "        SwarmVerifierV4.registerAnomaly(\n"
    "            transporterId: transporterId,\n"
    "            submissionSig: submissionSig,\n"
    "            anomalyConfidence: anomalyConfidence,\n"
    "            quorumIds: quorumIds,\n"
    "            bidPrices: bidPrices\n"
    "        )\n"
    "    }\n"
    "}"
    )

    conf_ufix64    = int(state.anomaly_confidence * 1e8)
    quorum_ids     = list(quorum.keys())
    bid_prices_ufix = [int(PAYMENT_PER_AUDITOR * 1e8)] * len(quorum_ids)

    def build(tx):
        tx = tx.add_arguments(String(state.pub_hex))
        tx = tx.add_arguments(String(state.current_event_id))
        tx = tx.add_arguments(UFix64(conf_ufix64))
        tx = tx.add_arguments(Array([String(i) for i in quorum_ids]))
        tx = tx.add_arguments(Array([UFix64(p) for p in bid_prices_ufix]))
        return tx

    with _flow_tx_lock:
        asyncio.run(_flow_tx_async(cadence, build, "registerAnomaly", wait_seal=True))


def _finalize_event_on_flow(event_id: str):
    if not FLOW_ENABLED:
        return

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String) {\n"
        "    prepare(signer: auth(Storage) &Account) {}\n"
        "    execute { SwarmVerifierV4.finalizeEvent(eventId: eventId) }\n"
        "}"
    )

    def build(tx):
        return tx.add_arguments(String(event_id))

    with _flow_tx_lock:
        asyncio.run(_flow_tx_async(cadence, build, "finalizeEvent", wait_seal=True))


# ── CLI ────────────────────────────────────────────────────────────────────────

def cli():
    print("\nMock Transporter ready.")
    print("Commands:  [a] trigger anomaly    [r] show registry    [q] quit\n")
    while True:
        try:
            cmd = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if cmd == "a":
            with state.registry_lock:
                n = len(state.registry)
            if n == 0:
                print("[!] No auditors registered yet. Wait for a beacon.")
            elif state.system_status != "IDLE":
                print(f"[!] Busy ({state.system_status}) — wait for current cycle to finish.")
            else:
                threading.Thread(target=trigger_anomaly, daemon=True).start()

        elif cmd == "r":
            with state.registry_lock:
                if not state.registry:
                    print("  No auditors registered.")
                for pub, info in state.registry.items():
                    age = time.time() - info["last_seen"]
                    print(f"  {info['ip']}  pubkey={pub[:12]}...  last_seen={age:.0f}s ago")

        elif cmd == "q":
            print("Exiting.")
            break

        else:
            print("  Unknown command.")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _register_transporter_on_flow()
    threading.Thread(target=multicast_listener, daemon=True).start()
    threading.Thread(target=bid_listener,       daemon=True).start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), TransporterHTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[HTTP] Server on 0.0.0.0:{HTTP_PORT}")

    cli()