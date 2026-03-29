"""
auditor_node.py — SwarmVerifier Auditor Node
Architecture: PL_Genesis Hackathon 2026

Protocol flow:
  1. Broadcast signed beacon every 5 s                (PKT_BEACON  0x01, 129 B)
  2. Receive PKT_ANOMALY                              (0x03, 133 B)
       → verify transporter ECDSA-P256/SHA-256 sig
       → store transporter pubkey + IP
       → send signed bid to BID_PORT                 (PKT_BID     0x02, 137 B)
  3. Wait up to QUORUM_WAIT_S for PKT_QUORUM         (0x04, 129 B)
       → verify sig with stored transporter pubkey
       → confirm bytes[1:65] == own pubkey
  4. x402 HTTP flow:
       GET  /data?pubkey=<hex>  →  402 + {nonce}
       POST /pay  {pubkey, signature, deposit}  →  200 {csv, payload}
         • deposit field triggers the transporter to call Flow.submitDeposit()
           before streaming the CSV. A 503 response means the on-chain lock
           failed — abort rather than retrying (prevents double-lock).
  5. Run Random Forest model on last 50 rows of CSV (shape 50×7)
  6. Submit signed verdict:
       • flow_enabled=True  → SwarmVerifierV4.submitVerdict() on testnet
       • flow_enabled=False → POST /verdict to mock_transporter

Packet formats (must match config.h):
  Beacon  (0x01, 129 B): [type 1B][pubkey 64B][sig 64B]
  Bid     (0x02, 137 B): [type 1B][pubkey 64B][price float64 LE 8B][sig over bytes[0:73] 64B]
  Anomaly (0x03, 133 B): [type 1B][pubkey 64B][conf float32 LE 4B][sig 64B]
  Quorum  (0x04, 129 B): [type 1B][nominated_pubkey 64B][sig 64B]

Verdict canonical string (signed by auditor, recorded on-chain):
  "<128-hex-pubkey>:<0|1>:<confidence:.4f>"
  int() cast is mandatory — Python bool → "True", int(True) → "1".

Environment variables (required when --flow-enabled):
  FLOW_ACCOUNT_ADDR  — auditor's Flow account address, e.g. "0xabcd1234ef567890"
  FLOW_ACCOUNT_KEY   — hex P-256 private key for that account (no 0x prefix)
"""

import argparse
import asyncio
import hashlib
import io
import os
import socket
import struct
import threading
import time
from dotenv import load_dotenv
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import requests
from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigencode_string
from flow_py_sdk import flow_client
from flow_py_sdk.cadence import String, UFix64, Bool, Address
from flow_py_sdk.tx import Tx, ProposalKey
from flow_py_sdk.signer import Signer as FlowSigner

load_dotenv()

# ── Column names (must match Pico's imu_buildCsvBuffer()) ────────────────────
CSV_COLUMNS  = ['timestamp_ms', 'ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']
FEATURE_COLS = ['ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']

# ── Sizes (must match config.h) ───────────────────────────────────────────────
CSV_BUFFER_SAMPLES = 75    # rows the Pico serves
WINDOW_SIZE        = 50    # rows fed to Random Forest (last 50)
INPUT_TENSOR_SIZE  = 350   # 50 × 7

# ── Network constants (must match config.h) ───────────────────────────────────
MULTICAST_GROUP = '239.0.0.1'
MULTICAST_PORT  = 5005
BID_PORT        = 5006
HTTP_PORT       = 8080

# ── Timing ────────────────────────────────────────────────────────────────────
BEACON_INTERVAL_S = 5.0
QUORUM_WAIT_S     = 120.0   # wait for PKT_QUORUM after sending a bid
DELIVERY_WAIT_S   = 90.0    # x402 HTTP timeout (generous — submitDeposit blocks Pico)
VERDICT_WAIT_S    = 90.0    # Flow TX timeout

# ── Economics ────────────────────────────────────────────────────────────────
DEPOSIT_AMOUNT = 0.5        # FLOW locked as bond at POST /pay
                            # returned if verdict submitted (aligned or deviated)
                            # forfeited if silent after receiving data

# ── Flow defaults (override via CLI args or env vars) ────────────────────────
FLOW_API_URL_DEFAULT       = "http://localhost:8080"    # mock_transporter
FLOW_CONTRACT_ADDR_DEFAULT = "0xfcd23c8d1553708a"       # testnet placeholder

# ── Cadence scripts ───────────────────────────────────────────────────────────
_REGISTER_NODE_SCRIPT = """
import SwarmVerifierV4 from {contract_addr}
transaction(nodeId: String, stake: UFix64) {{
    prepare(signer: &Account) {{}}
    execute {{
        SwarmVerifierV4.registerNode(nodeId: nodeId, stake: stake)
    }}
}}
"""

_SUBMIT_VERDICT_SCRIPT = """
import SwarmVerifierV4 from {contract_addr}
transaction(
    eventId: String,
    auditorId: String,
    verdict: Bool,
    confidence: UFix64,
    payloadSignature: String,
    verdictSignature: String
) {{
    prepare(signer: &Account) {{}}
    execute {{
        SwarmVerifierV4.submitVerdict(
            eventId: eventId,
            auditorId: auditorId,
            verdict: verdict,
            confidence: confidence,
            payloadSignature: payloadSignature,
            verdictSignature: verdictSignature
        )
    }}
}}
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _verdict_canonical(pub_hex: str, verdict_bool: bool, confidence: float) -> bytes:
    """
    Canonical string the auditor signs. Must match Pico's C-side reconstruction:
      snprintf(buf, ..., "%s:%d:%.4f", pub_hex, (int)verdict, confidence)
    """
    return f"{pub_hex}:{int(verdict_bool)}:{confidence:.4f}".encode()


class _EcdsaSigner(FlowSigner):
    """Flow SDK signer that uses SHA3-256 (required by Flow protocol)."""
    def __init__(self, sk: SigningKey):
        self._sk = sk

    def sign(self, message: bytes, tag: Optional[bytes] = None) -> bytes:
        if tag is not None:
            message = tag + message
        return self._sk.sign(
            message,
            hashfunc=hashlib.sha3_256,
            sigencode=sigencode_string,
        )


# ─────────────────────────────────────────────────────────────────────────────
class AuditorNode:
    """
    One auditor process. Manages its own identity, beacon thread, and listener
    thread. All per-event state is reset at the start of each anomaly cycle.
    """

    def __init__(
        self,
        key_path:           str   = "./identity.pem",
        bid_price:          float = 1.0,
        deposit:            float = DEPOSIT_AMOUNT,
        flow_api_url:       str   = FLOW_API_URL_DEFAULT,
        flow_contract_addr: str   = FLOW_CONTRACT_ADDR_DEFAULT,
        flow_enabled:       bool  = False,
    ):
        # ── Cryptographic identity ────────────────────────────────────────────
        self.sk, self.vk = self._load_or_generate_keypair(key_path)
        self.pub_bytes   = self.vk.to_string()   # 64 bytes X‖Y, no 0x04
        self.pub_hex     = self.pub_bytes.hex()  # 128 hex chars

        # ── Config ────────────────────────────────────────────────────────────
        self.bid_price          = float(bid_price)
        self.deposit_amount     = float(deposit)
        self.flow_api_url       = flow_api_url.rstrip('/')
        self.flow_contract_addr = flow_contract_addr
        self.flow_enabled       = flow_enabled

        # ── Per-event state ───────────────────────────────────────────────────
        # All fields protected by _state_lock.
        # Reset at the start of each anomaly cycle to prevent cross-contamination.
        self._state_lock         = threading.Lock()
        self._transporter_pubkey: Optional[bytes] = None   # 64 raw bytes
        self._transporter_ip:     Optional[str]   = None
        self._current_event_id:   Optional[str]   = None   # submissionSig hex
        self._quorum_event        = threading.Event()      # set on PKT_QUORUM

        # ── ML model ─────────────────────────────────────────────────────────
        print("[*] Loading Random Forest model (Model B)...")
        try:
            self.model = joblib.load('./models/auditor_model.joblib')
            print("[*] Model loaded.")
        except FileNotFoundError:
            print("[WARN] ./models/auditor_model.joblib not found — ML verification skipped.")
            self.model = None

        # ── Register on Flow testnet ──────────────────────────────────────────
        if self.flow_enabled:
            self._register_on_flow()

        print(f"[*] Auditor ready. pubkey={self.pub_hex[12:]}...")
        print(f"[*] Bid price:   {self.bid_price} FLOW")
        print(f"[*] Deposit:     {self.deposit_amount} FLOW")
        print(f"[*] Flow submit: {'ENABLED → testnet' if self.flow_enabled else 'DISABLED (mock /verdict)'}")

    # ─────────────────────────────────────────────────────────────────────────
    # Crypto helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _load_or_generate_keypair(key_path: str):
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                sk = SigningKey.from_pem(f.read())
            print(f"[*] Loaded identity from {key_path}")
        else:
            sk = SigningKey.generate(curve=NIST256p)
            with open(key_path, "wb") as f:
                f.write(sk.to_pem())
            print(f"[*] Generated new identity → {key_path}")
        return sk, sk.verifying_key

    def _sign(self, data: bytes) -> bytes:
        """ECDSA-P256/SHA-256 — matches Pico's crypto_sign() which uses SHA-256."""
        return self.sk.sign(data, hashfunc=hashlib.sha256)

    @staticmethod
    def _verify(payload: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
        """Verify ECDSA-P256/SHA-256 signature. Returns False instead of raising."""
        try:
            vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
            return vk.verify(sig, payload, hashfunc=hashlib.sha256)
        except (BadSignatureError, Exception):
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Beacon broadcaster
    # ─────────────────────────────────────────────────────────────────────────

    def broadcast_presence(self):
        """
        Runs forever in a daemon thread. Sends PKT_BEACON every BEACON_INTERVAL_S.
        PKT_BEACON (0x01, 129 bytes):
          byte   0    : 0x01
          bytes  1-64 : pubkey (X‖Y, 64 raw bytes)
          bytes 65-128: ECDSA-P256/SHA-256 sig over bytes[0:65]
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        header = bytes([0x01]) + self.pub_bytes              # 65 bytes
        sig    = self._sign(header)                          # 64 bytes
        packet = header + sig                                # 129 bytes
        assert len(packet) == 129, f"Beacon packet wrong length: {len(packet)}"

        print(f"[Beacon] Broadcasting to {MULTICAST_GROUP}:{MULTICAST_PORT} every {BEACON_INTERVAL_S}s")
        while True:
            try:
                sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
            except Exception as e:
                print(f"[Beacon] Send error: {e}")
            time.sleep(BEACON_INTERVAL_S)

    # ─────────────────────────────────────────────────────────────────────────
    # Main listener — runs forever in a daemon thread
    # ─────────────────────────────────────────────────────────────────────────

    def listen(self):
        """
        Joins the multicast group and dispatches incoming packets.
        SO_REUSEPORT lets multiple auditors run on the same host for testing.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Windows doesn't have SO_REUSEPORT
        sock.bind(('', MULTICAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print(f"[*] Listening on {MULTICAST_GROUP}:{MULTICAST_PORT}")

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if not data:
                    continue
                pkt_type = data[0]
                if   pkt_type == 0x03 and len(data) == 133:
                    self._handle_anomaly(data, addr)
                elif pkt_type == 0x04 and len(data) == 129:
                    self._handle_quorum(data, addr)
                # 0x01 (beacon echo) and 0x02 (bids) are ignored
            except Exception as e:
                print(f"[Listen] Error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # PKT_ANOMALY (0x03) handler
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_anomaly(self, data: bytes, addr):
        """
        PKT_ANOMALY (0x03, 133 bytes):
          byte   0    : 0x03
          bytes  1-64 : transporter pubkey
          bytes 65-68 : anomaly confidence (float32 LE)
          bytes 69-132: ECDSA sig over bytes[0:69]
        """
        transporter_pubkey = data[1:65]
        confidence         = struct.unpack('<f', data[65:69])[0]
        sig                = data[69:133]

        if not self._verify(data[0:69], sig, transporter_pubkey):
            print(f"[WARN] Anomaly from {addr[0]} — bad sig. Dropping.")
            return

        print(f"\n[Anomaly] ✓ Verified | transporter={addr[0]} | confidence={confidence:.4f}")

        # Fresh Event per cycle — prevents a stale quorum signal from a previous
        # cycle triggering the x402 fetch in this one.
        cycle_event = threading.Event()

        with self._state_lock:
            self._transporter_pubkey = bytes(transporter_pubkey)
            self._transporter_ip     = addr[0]
            self._current_event_id   = None
            self._quorum_event       = cycle_event

        self._send_bid(addr[0])

        threading.Thread(
            target=self._wait_for_quorum_then_fetch,
            args=(cycle_event,),
            daemon=True,
            name="quorum-wait",
        ).start()

    # ─────────────────────────────────────────────────────────────────────────
    # PKT_BID sender
    # ─────────────────────────────────────────────────────────────────────────

    def _send_bid(self, transporter_ip: str):
        """
        PKT_BID (0x02, 137 bytes):
          byte   0    : 0x02
          bytes  1-64 : auditor pubkey
          bytes 65-72 : bid price (float64 LE)
          bytes 73-136: ECDSA sig over bytes[0:73]

        Sent unicast to BID_PORT on the transporter's IP.
        """
        header   = bytes([0x02]) + self.pub_bytes + struct.pack('<d', self.bid_price)
        sig      = self._sign(header)
        packet   = header + sig
        assert len(packet) == 137

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Send 3 times to handle UDP drop
            for attempt in range(3):
                sock.sendto(packet, (transporter_ip, BID_PORT))
                time.sleep(0.3)
            sock.close()
            print(f"[Bid] Sent {self.bid_price} FLOW bid to {transporter_ip}:{BID_PORT}")
        except Exception as e:
            print(f"[Bid] Send error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Quorum wait + x402 trigger
    # ─────────────────────────────────────────────────────────────────────────

    def _wait_for_quorum_then_fetch(self, cycle_event: threading.Event):
        """
        Blocks until either:
          • PKT_QUORUM arrives confirming our nomination, or
          • QUORUM_WAIT_S elapses (we were not selected — stand down)
        """
        selected = cycle_event.wait(timeout=QUORUM_WAIT_S)
        if not selected:
            print(f"[Quorum] Not selected within {QUORUM_WAIT_S}s — standing down.")
            return

        with self._state_lock:
            transporter_ip = self._transporter_ip

        if not transporter_ip:
            print("[Quorum] No transporter IP stored — cannot proceed.")
            return

        self._execute_x402_fetch(transporter_ip)

    # ─────────────────────────────────────────────────────────────────────────
    # PKT_QUORUM (0x04) handler
    # ─────────────────────────────────────────────────────────────────────────

    def _handle_quorum(self, data: bytes, addr):
        """
        PKT_QUORUM (0x04, 129 bytes):
          byte   0    : 0x04
          bytes  1-64 : nominated pubkey (the auditor being selected)
          bytes 65-128: ECDSA sig over bytes[0:65] — signed by transporter

        Accepted only if:
          1. Sig verifies against stored transporter pubkey
          2. Nominated pubkey == our own pubkey
        """
        nominated_pubkey = data[1:65]
        sig              = data[65:129]

        with self._state_lock:
            transporter_pubkey = self._transporter_pubkey
            cycle_event        = self._quorum_event

        if transporter_pubkey is None:
            return  # no active anomaly cycle

        if not self._verify(data[0:65], sig, transporter_pubkey):
            print(f"[WARN] PKT_QUORUM from {addr[0]} — bad sig. Ignoring.")
            return

        if nominated_pubkey != self.pub_bytes:
            return  # directed at a different auditor — ignore silently

        print(f"[Quorum] ✓ Selected! Proceeding to x402 fetch.")
        cycle_event.set()

    # ─────────────────────────────────────────────────────────────────────────
    # x402 HTTP flow
    # ─────────────────────────────────────────────────────────────────────────

    def _execute_x402_fetch(self, transporter_ip: str):
        """
        Step 1 — GET /data?pubkey=<hex>
          → 402 + {nonce}      : proceed
          → 403                : not in quorum, stand down
          → other              : unexpected, abort

        Step 2 — POST /pay  {pubkey, signature, deposit}
          → 200 + {csv, payload} : run ML verification
          → 503                  : transporter's Flow.submitDeposit() failed
                                   (deposit not locked on-chain) — abort
          → other                : unexpected, abort

        The 200 payload must contain:
          {
            transporter_pubkey, auditor_pubkey,
            anomaly_confidence, timestamp_ms,
            event_id,           ← submissionSig, the Flow contract's event key
            deposit,            ← the deposit amount actually recorded on-chain
            payload_signature,  ← transporter's sig tying this data to the event
          }
        """
        base_url = f"http://{transporter_ip}:{HTTP_PORT}"

        try:
            # ── Step 1: GET /data ─────────────────────────────────────────────
            resp = requests.get(
                f"{base_url}/data",
                params={"pubkey": self.pub_hex},
                timeout=DELIVERY_WAIT_S,
            )

            if resp.status_code == 403:
                reason = resp.json().get("error", "no detail") if resp.content else "no detail"
                print(f"[x402] 403 — {reason}. Standing down.")
                return

            if resp.status_code != 402:
                print(f"[x402] Unexpected status on GET /data: {resp.status_code}. Aborting.")
                return

            nonce_hex = resp.json().get("nonce", "")
            if not nonce_hex:
                print("[x402] 402 missing nonce. Aborting.")
                return
            print(f"[x402] 402 received. nonce={nonce_hex[:16]}...")

            # ── Step 2: POST /pay ─────────────────────────────────────────────
            # The deposit field tells the transporter how much FLOW to lock on-chain
            # via Flow.submitDeposit(). The transporter MUST seal that TX before
            # responding — hence DELIVERY_WAIT_S is generous (seal takes ~10-15 s).
            nonce_bytes = bytes.fromhex(nonce_hex)
            sig_hex     = self._sign(nonce_bytes).hex()

            pay_resp = requests.post(
                f"{base_url}/pay",
                json={
                    "pubkey":    self.pub_hex,
                    "signature": sig_hex,
                    "deposit":   self.deposit_amount,
                },
                timeout=DELIVERY_WAIT_S,
            )

            if pay_resp.status_code == 503:
                print("[x402] 503 — transporter Flow.submitDeposit() failed. "
                      "Deposit not locked on-chain. Aborting.")
                return

            if pay_resp.status_code != 200:
                print(f"[x402] POST /pay rejected: {pay_resp.status_code}. Aborting.")
                return

            body    = pay_resp.json()
            csv_raw = body.get("csv", "")
            payload = body.get("payload", {})

            if not csv_raw:
                print("[x402] 200 missing csv. Aborting.")
                return
            if not payload:
                print("[x402] 200 missing payload. Aborting.")
                return

            # event_id = submissionSig — the Flow contract's unique event key
            event_id = payload.get("event_id", "")
            if not event_id:
                print("[x402] payload.event_id missing — cannot identify event on-chain. Aborting.")
                return

            # payload_signature ties this verdict cryptographically to the data received
            payload_sig = payload.get("payload_signature", "")
            if not payload_sig:
                print("[x402] payload.payload_signature missing — verdict chain broken. Aborting.")
                return

            deposit_confirmed = payload.get("deposit", 0.0)
            print(f"[x402] ✓ Data access granted. "
                  f"eventId={event_id[:16]}...  deposit_locked={deposit_confirmed} FLOW")

            with self._state_lock:
                self._current_event_id = event_id

            self._run_verification(csv_raw, payload_sig)

        except requests.exceptions.ConnectionError as e:
            print(f"[x402] Connection error: {e}")
        except requests.exceptions.Timeout:
            print(f"[x402] Timeout after {DELIVERY_WAIT_S}s")
        except Exception as e:
            print(f"[x402] Unexpected error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # ML verification
    # ─────────────────────────────────────────────────────────────────────────

    def _run_verification(self, csv_raw: str, payload_signature: str):
        """
        1. Parse CSV — validate column names
        2. Take last WINDOW_SIZE rows (drop is at tail of the 75-row buffer)
        3. Flatten to (1, INPUT_TENSOR_SIZE) — must be 50 × 7 = 350
        4. Random Forest predict() + predict_proba()
        5. Submit signed verdict
        """
        if self.model is None:
            print("[ML] No model loaded — submitting fallback verdict (False, 0.5).")
            self._submit_verdict(False, 0.5, payload_signature)
            return

        try:
            df = pd.read_csv(io.StringIO(csv_raw), names=CSV_COLUMNS, header=0)

            missing = [c for c in FEATURE_COLS if c not in df.columns]
            if missing:
                print(f"[ML] CSV missing columns: {missing}. Got: {list(df.columns)}. Aborting.")
                return

            data_window = df[FEATURE_COLS].values

            if len(data_window) >= WINDOW_SIZE:
                data_window = data_window[-WINDOW_SIZE:]
            else:
                print(f"[ML] Only {len(data_window)} rows, zero-padding to {WINDOW_SIZE}.")
                pad = np.zeros((WINDOW_SIZE - len(data_window), len(FEATURE_COLS)))
                data_window = np.vstack((pad, data_window))

            X = data_window.flatten().reshape(1, -1)
            if X.shape[1] != INPUT_TENSOR_SIZE:
                print(f"[ML] Shape mismatch: got {X.shape[1]}, expected {INPUT_TENSOR_SIZE}. Aborting.")
                return

            prediction    = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            confidence    = float(max(probabilities))
            verdict_bool  = bool(prediction == 1)

            print(f"[ML] Verdict: {'DROP' if verdict_bool else 'NORMAL'} | confidence={confidence:.4f}")
            self._submit_verdict(verdict_bool, confidence, payload_signature)

        except Exception as e:
            print(f"[ML] Error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Verdict submission
    # ─────────────────────────────────────────────────────────────────────────

    def _submit_verdict(self, verdict_bool: bool, confidence: float, payload_signature: str):
        """
        Builds and submits the verdict. Routes to Flow or mock based on config.

        verdict_sig covers: "<pubkey>:<0|1>:<confidence:.4f>"
        payload_signature was issued by the transporter in the 200 response — it
        cryptographically ties this verdict to the specific IMU data received.
        """
        with self._state_lock:
            event_id = self._current_event_id

        if not event_id:
            print("[Verdict] No event_id available — aborting.")
            return

        canonical = _verdict_canonical(self.pub_hex, verdict_bool, confidence)
        sig_hex   = self._sign(canonical).hex()

        body = {
            "event_id":           event_id,
            "auditor_pubkey":     self.pub_hex,
            "verdict":            verdict_bool,
            "verdict_confidence": confidence,
            "payload_signature":  payload_signature,
            "verdict_signature":  sig_hex,
            "csv_cid":            "",   # transporter fills post-consensus
        }

        if self.flow_enabled:
            self._submit_to_flow(body)
        else:
            self._submit_to_mock(body)

    # ─────────────────────────────────────────────────────────────────────────
    # Mock verdict submission (flow_enabled=False)
    # ─────────────────────────────────────────────────────────────────────────

    def _submit_to_mock(self, body: dict):
        url = f"{self.flow_api_url}/verdict"
        try:
            r = requests.post(url, json=body, timeout=10)
            if r.status_code == 200:
                print(f"[Mock] ✓ Verdict submitted to mock transporter.")
            else:
                print(f"[Mock] Verdict rejected: HTTP {r.status_code} — {r.text[:120]}")
        except Exception as e:
            print(f"[Mock] Network error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Live Flow verdict submission (flow_enabled=True)
    # ─────────────────────────────────────────────────────────────────────────

    def _submit_to_flow(self, body: dict):
        """Sync wrapper — asyncio.run() is safe here (called from a thread)."""
        asyncio.run(self._submit_to_flow_async(body))

    async def _submit_to_flow_async(self, body: dict):
        flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "")
        flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "")

        if not flow_addr or not flow_key:
            print("[Flow] FLOW_ACCOUNT_ADDR or FLOW_ACCOUNT_KEY not set — falling back to mock.")
            self._submit_to_mock(body)
            return

        script            = _SUBMIT_VERDICT_SCRIPT.format(contract_addr=self.flow_contract_addr)
        confidence_ufix64 = int(round(body["verdict_confidence"] * 1e8))
        sk                = SigningKey.from_string(
                                bytes.fromhex(flow_key.removeprefix("0x")), curve=NIST256p)
        signer            = _EcdsaSigner(sk)
        addr              = Address.from_hex(flow_addr)

        for attempt in range(3):
            try:
                async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                    account      = await client.get_account(address=addr)
                    account_key  = account.keys[0]
                    latest_block = await client.get_latest_block(is_sealed=True)

                    tx = (
                        Tx(code=script)
                        .add_arguments(String(body["event_id"]))
                        .add_arguments(String(body["auditor_pubkey"]))
                        .add_arguments(Bool(body["verdict"]))
                        .add_arguments(UFix64(confidence_ufix64))
                        .add_arguments(String(body["payload_signature"]))
                        .add_arguments(String(body["verdict_signature"]))
                        .with_reference_block_id(latest_block.id)
                        .with_gas_limit(999)
                        .with_proposal_key(ProposalKey(
                            key_address         = addr,
                            key_id              = account_key.index,
                            key_sequence_number = account_key.sequence_number,
                        ))
                        .with_payer(addr)
                        .add_authorizers(addr)
                        .with_envelope_signature(addr, account_key.index, signer)
                    )

                    result = await client.execute_transaction(
                        tx, wait_for_seal=True, timeout=float(VERDICT_WAIT_S))
                    tx_id = result.id.hex() if hasattr(result, 'id') else "unknown"
                    print(f"[Flow] ✓ submitVerdict sealed — "
                          f"https://testnet.flowscan.io/tx/{tx_id}")
                    return

            except Exception as e:
                err = str(e)
                if "sequence number" in err and attempt < 2:
                    print(f"[Flow] Seq number mismatch (attempt {attempt+1}) — retrying in 3s...")
                    await asyncio.sleep(3)
                    continue
                print(f"[Flow] submitVerdict error: {e}")
                return

    # ─────────────────────────────────────────────────────────────────────────
    # Flow node registration (called at startup when flow_enabled=True)
    # ─────────────────────────────────────────────────────────────────────────

    def _register_on_flow(self):
        """
        Calls SwarmVerifierV4.registerNode() once. Idempotent — the contract
        pre-condition rejects duplicates gracefully, so this is safe on every run.
        """
        flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "")
        flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "")
        if not flow_addr or not flow_key:
            print("[Flow] Cannot registerNode — FLOW_ACCOUNT_ADDR/KEY not set.")
            return
        asyncio.run(self._register_on_flow_async(
            flow_addr.removeprefix("0x"),
            flow_key.removeprefix("0x")))

    async def _register_on_flow_async(self, flow_addr: str, flow_key: str):
        script = _REGISTER_NODE_SCRIPT.format(contract_addr=self.flow_contract_addr)
        sk     = SigningKey.from_string(bytes.fromhex(flow_key), curve=NIST256p)
        signer = _EcdsaSigner(sk)
        addr   = Address.from_hex(flow_addr)

        for attempt in range(3):
            try:
                async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                    account      = await client.get_account(address=addr)
                    account_key  = account.keys[0]
                    latest_block = await client.get_latest_block(is_sealed=True)

                    tx = (
                        Tx(code=script)
                        .add_arguments(String(self.pub_hex))
                        .add_arguments(UFix64(int(10.0 * 1e8)))   # 10 FLOW stake
                        .with_reference_block_id(latest_block.id)
                        .with_gas_limit(999)
                        .with_proposal_key(ProposalKey(
                            key_address         = addr,
                            key_id              = account_key.index,
                            key_sequence_number = account_key.sequence_number,
                        ))
                        .with_payer(addr)
                        .add_authorizers(addr)
                        .with_envelope_signature(addr, account_key.index, signer)
                    )

                    result = await client.execute_transaction(
                        tx, wait_for_seal=True, timeout=60.0)
                    tx_id = result.id.hex() if hasattr(result, 'id') else "unknown"
                    print(f"[Flow] ✓ registerNode sealed — "
                          f"https://testnet.flowscan.io/tx/{tx_id}")
                    return

            except Exception as e:
                err = str(e)
                if "already registered" in err:
                    print("[Flow] Auditor already registered on-chain — skipping.")
                    return
                if "sequence number" in err and attempt < 2:
                    print(f"[Flow] Seq mismatch (attempt {attempt+1}) — retrying in 3s...")
                    await asyncio.sleep(3)
                    continue
                print(f"[Flow] registerNode error: {e}")
                return


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SwarmVerifier Auditor Node")
    parser.add_argument("--key-file",  default="./identity.pem",
                        help="Path to PEM file for auditor identity (created if absent).")
    parser.add_argument("--bid-price", type=float, default=1.0,
                        help="FLOW tokens to bid per verification job.")
    parser.add_argument("--deposit",   type=float, default=DEPOSIT_AMOUNT,
                        help="FLOW tokens locked as bond when unlocking CSV data.")
    parser.add_argument("--flow-url",  default=os.environ.get("FLOW_API_URL", FLOW_API_URL_DEFAULT),
                        help="Base URL for verdict submission (mock transporter or live).")
    parser.add_argument("--flow-contract", default=os.environ.get("FLOW_CONTRACT_ADDR",
                                                                   FLOW_CONTRACT_ADDR_DEFAULT),
                        help="SwarmVerifierV4 contract address on Flow Testnet.")
    parser.add_argument("--flow-enabled", action="store_true", default=False,
                        help="Submit verdicts to the live Flow contract. "
                             "Requires FLOW_ACCOUNT_ADDR and FLOW_ACCOUNT_KEY env vars.")
    args = parser.parse_args()

    if args.flow_enabled:
        missing = [v for v in ("FLOW_ACCOUNT_ADDR", "FLOW_ACCOUNT_KEY") if not os.environ.get(v)]
        if missing:
            print(f"[WARN] --flow-enabled set but missing env vars: {missing}")
            print("[WARN] Verdict submissions will fall back to mock until these are set.")

    node = AuditorNode(
        key_path           = args.key_file,
        bid_price          = args.bid_price,
        deposit            = args.deposit,
        flow_api_url       = args.flow_url,
        flow_contract_addr = args.flow_contract,
        flow_enabled       = args.flow_enabled,
    )

    threading.Thread(target=node.broadcast_presence, daemon=True, name="beacon").start()
    threading.Thread(target=node.listen,             daemon=True, name="listener").start()

    print("[*] Auditor running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")


if __name__ == "__main__":
    main()