"""
mock_transporter.py
Simulates the Pico 2W Transporter for local auditor testing.

Implements the full protocol:
  - UDP multicast: receives beacons (0x01), receives bids (0x02), broadcasts anomaly (0x03)
  - HTTP server: GET /data  → 402 + nonce
                 POST /pay  → 200 with CSV + signed payload
                 POST /verdict → collects verdicts, runs consensus, prints result
"""

import socket
import struct
import hashlib
import secrets
import threading
import requests
import time
import json
import numpy as np
from http.server import HTTPServer, BaseHTTPRequestHandler
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError

# ── Protocol constants (must match config.h and auditor.py) ──────────────────
MULTICAST_GROUP    = "239.0.0.1"
MULTICAST_PORT     = 5005
BID_PORT           = 5006   # dedicated unicast port for bid reception
HTTP_PORT          = 8080

CSV_BUFFER_SAMPLES = 75
WINDOW_SIZE        = 50

BID_WINDOW_S       = 0.6    # how long to collect bids before selecting quorum
VERDICT_TIMEOUT_S  = 30.0   # how long to wait for all verdicts

# Reputation formula constants (must match SwarmVerifier.cdc)
ALPHA = 10.0
BETA  = 5.0

# ── Flow testnet config ───────────────────────────────────────────────────────
# Set FLOW_ENABLED = False to skip on-chain quorum ranking during local testing.
FLOW_ENABLED         = False   # flip to True once contract is deployed
FLOW_REST_URL        = "https://rest-testnet.onflow.org/v1/scripts"
FLOW_CONTRACT_ADDR   = "0xYOUR_TESTNET_ADDRESS"   # replace after deployment
FLOW_CONTRACT_NAME   = "SwarmVerifierV2"
QUORUM_SIZE          = 3       # max auditors in quorum


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
    Generates a CSV that looks like a real drop event:
      - First ~40 rows: normal idle motion (low linear accel)
      - Last ~35 rows:  drop signature (near-zero accel briefly, then impact spike)
    Columns: timestamp_ms,ax,ay,az,qw,qx,qy,qz
    """
    rows = []
    t    = int(time.time() * 1000) - n_rows * 20  # 50Hz → 20ms per sample

    for i in range(n_rows):
        phase = i / n_rows

        if phase < 0.5:
            # Idle: small random noise
            ax, ay, az = np.random.normal(0, 0.05, 3)
        elif phase < 0.75:
            # Free-fall: near-zero linear acceleration
            ax, ay, az = np.random.normal(0, 0.01, 3)
        else:
            # Impact spike
            ax = np.random.normal(0,   2.0)
            ay = np.random.normal(0,   2.0)
            az = np.random.normal(-9.8, 3.0)

        # Quaternion: nearly identity with tiny drift
        qw = 1.0 + np.random.normal(0, 0.005)
        qx, qy, qz = np.random.normal(0, 0.005, 3)

        rows.append(f"{t},{ax:.6f},{ay:.6f},{az:.6f},{qw:.6f},{qx:.6f},{qy:.6f},{qz:.6f}")
        t += 20

    header = "timestamp_ms,ax,ay,az,qw,qx,qy,qz"
    return header + "\n" + "\n".join(rows)


# ── Shared transporter state ──────────────────────────────────────────────────

class TransporterState:
    def __init__(self):
        self.sk        = SigningKey.generate(curve=NIST256p)
        self.vk        = self.sk.verifying_key
        self.pub_bytes = self.vk.to_string()
        self.pub_hex   = self.pub_bytes.hex()

        # Auditor registry: pubkey_hex → { ip, last_seen }
        self.registry: dict[str, dict] = {}
        self.registry_lock = threading.Lock()

        # Bid collection
        self.bids: list[dict] = []          # [ {pubkey_hex, ip} ]
        self.bids_lock        = threading.Lock()
        self.collecting_bids  = False

        # Quorum (set after bid window closes)
        self.quorum: set[str] = set()       # pubkey_hex strings

        # x402 nonce: pubkey_hex → nonce_bytes (refreshed each GET /data)
        self.nonces: dict[str, bytes] = {}
        self.nonces_lock = threading.Lock()

        # Verdict pool: pubkey_hex → { verdict, confidence, signature }
        self.verdicts: dict[str, dict] = {}
        self.verdicts_lock = threading.Lock()
        self.collecting_verdicts = False
        self.expected_verdicts   = 0

        # Current anomaly
        self.anomaly_confidence: float = 0.93
        self.csv_data: str = ""

        print(f"[Transporter] pubkey={self.pub_hex[:16]}...")

    def build_anomaly_packet(self) -> bytes:
        """
        133 bytes:
          byte 0      : 0x03
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

    def build_payload_json(self, auditor_pubkey_hex: str) -> dict:
        """Signed JSON payload served inside the x402 200 response."""
        body = {
            "transporter_pubkey":    self.pub_hex,
            "winning_auditor_pubkey": auditor_pubkey_hex,
            "anomaly_confidence":    self.anomaly_confidence,
            "timestamp_ms":          int(time.time() * 1000),
        }
        canonical = json.dumps(body, separators=(',', ':')).encode()
        sig_hex   = _sign(self.sk, canonical).hex()
        body["payload_signature"] = sig_hex
        return body


state = TransporterState()


# ── HTTP handler ──────────────────────────────────────────────────────────────

class TransporterHTTP(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Suppress default Apache-style logs; we print our own
        pass

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed    = urlparse(self.path)
        client_ip = self.client_address[0]

        if parsed.path != "/data":
            self._send_json(404, {"error": "not found"})
            return

        # Auditor passes ?pubkey=<128 hex> so nonces are keyed by identity,
        # not IP. Fixes the nonce-overwrite bug when multiple auditors share a host.
        params     = parse_qs(parsed.query)
        pubkey_hex = params.get("pubkey", [None])[0]

        if not pubkey_hex or len(pubkey_hex) != 128:
            self._send_json(400, {"error": "missing or invalid ?pubkey query param"})
            return

        if not state.quorum:
            self._send_json(403, {"error": "no active quorum"})
            return

        if pubkey_hex not in state.quorum:
            print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... -> 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        nonce = secrets.token_bytes(16)
        with state.nonces_lock:
            state.nonces[pubkey_hex] = nonce

        print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... -> 402 nonce={nonce.hex()}")
        self._send_json(402, {
            "status":      "payment_required",
            "endpoint":    "/pay",
            "nonce":       nonce.hex(),
            "description": "Sign the nonce with your private key to receive IMU data",
        })

    def do_POST(self):
        length  = int(self.headers.get("Content-Length", 0))
        raw     = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/pay":
            self._handle_pay(body)
        elif self.path == "/verdict":
            self._handle_verdict(body)
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_pay(self, body: dict):
        client_ip = self.client_address[0]

        pubkey_hex = body.get("pubkey", "")
        sig_hex    = body.get("signature", "")

        if len(pubkey_hex) != 128 or len(sig_hex) != 128:
            self._send_json(400, {"error": "pubkey and signature must each be 128 hex chars"})
            return

        with state.nonces_lock:
            nonce = state.nonces.get(pubkey_hex)

        if not nonce:
            self._send_json(403, {"error": "no pending nonce for this pubkey -- call GET /data first"})
            return

        # Verify signature over nonce
        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(nonce, sig_bytes, pub_bytes):
            print(f"[HTTP] POST /pay from {client_ip} → 403 bad signature")
            self._send_json(403, {"error": "signature verification failed"})
            return

        # Quorum check
        if pubkey_hex not in state.quorum:
            print(f"[HTTP] POST /pay from {client_ip} → 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        print(f"[HTTP] POST /pay from {client_ip} pubkey={pubkey_hex[:12]}... -> 200 OK")
        payload = state.build_payload_json(pubkey_hex)
        self._send_json(200, {
            "csv":     state.csv_data,
            "payload": payload,
        })

        # Invalidate nonce
        with state.nonces_lock:
            state.nonces.pop(pubkey_hex, None)

    def _handle_verdict(self, body: dict):
        client_ip  = self.client_address[0]

        auditor_pub = body.get("auditor_pubkey", "")
        verdict     = body.get("verdict")
        confidence  = body.get("verdict_confidence")
        sig_hex     = body.get("auditor_verdict_signature", "")

        # Basic field validation
        if not all([auditor_pub, verdict is not None, confidence is not None, sig_hex]):
            self._send_json(400, {"error": "missing fields"})
            return

        if auditor_pub not in state.quorum:
            print(f"[HTTP] POST /verdict from {client_ip} → 403 not in quorum")
            self._send_json(403, {"error": "not in quorum"})
            return

        # Verify verdict signature
        # Canonical: "<pubkey_hex>:<0 or 1>:<confidence:.4f>"
        canonical = f"{auditor_pub}:{int(verdict)}:{float(confidence):.4f}".encode()
        try:
            pub_bytes = bytes.fromhex(auditor_pub)
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(canonical, sig_bytes, pub_bytes):
            print(f"[HTTP] POST /verdict from {client_ip} → 403 bad signature")
            self._send_json(403, {"error": "verdict signature verification failed"})
            return

        with state.verdicts_lock:
            if auditor_pub in state.verdicts:
                self._send_json(409, {"error": "verdict already received"})
                return
            state.verdicts[auditor_pub] = {
                "verdict":    bool(verdict),
                "confidence": float(confidence),
                "signature":  sig_hex,
                "ip":         client_ip,
            }
            count = len(state.verdicts)

        print(f"[HTTP] Verdict from {client_ip[:8]}... → {'DROP' if verdict else 'NORMAL'} "
              f"conf={confidence:.4f} ({count}/{state.expected_verdicts})")
        self._send_json(200, {"status": "received"})

        if count >= state.expected_verdicts:
            threading.Thread(target=_run_consensus, daemon=True).start()


# ── Consensus ─────────────────────────────────────────────────────────────────

def _run_consensus():
    with state.verdicts_lock:
        verdicts = dict(state.verdicts)

    if not verdicts:
        return

    confidences = [v["confidence"] for v in verdicts.values()]
    drop_votes  = sum(1 for v in verdicts.values() if v["verdict"])
    n           = len(verdicts)

    cswarm           = sum(confidences) / n
    consensus_result = drop_votes > (n // 2)

    print("\n" + "═" * 60)
    print(f"  CONSENSUS RESULT")
    print("═" * 60)
    print(f"  Auditors     : {n}")
    print(f"  Drop votes   : {drop_votes}/{n}")
    print(f"  Cswarm       : {cswarm:.4f}")
    print(f"  Consensus    : {'DROP CONFIRMED' if consensus_result else 'NORMAL — FALSE POSITIVE'}")
    print("─" * 60)

    for pub, v in verdicts.items():
        v_agent = v["confidence"]
        aligned = v["verdict"] == consensus_result
        delta   = ALPHA * (cswarm - v_agent) - (BETA if not aligned else 0.0)
        status  = "✓ aligned" if aligned else "✗ deviated"
        print(f"  {pub[:12]}...  verdict={'DROP' if v['verdict'] else 'NORM'}  "
              f"conf={v_agent:.4f}  ΔR={delta:+.4f}  {status}")

    print("═" * 60)
    print("  [NOTE] In production: upload CSV → Storacha, POST to Flow contract")
    print("═" * 60 + "\n")


# ── UDP listeners ─────────────────────────────────────────────────────────────
# Beacons arrive via multicast; bids are unicast to a dedicated port.
# Keeping them on separate sockets avoids the multicast socket silently dropping
# unicast packets on some Linux network configurations.

def multicast_listener():
    """Receives signed beacons (0x01) from auditors via multicast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', MULTICAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"[UDP] Multicast listener on {MULTICAST_GROUP}:{MULTICAST_PORT} (beacons)")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 129 and data[0] == 0x01:
            _handle_beacon(data, addr)


def bid_listener():
    """Receives signed bids (0x02) from auditors via unicast on BID_PORT."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', BID_PORT))

    print(f"[UDP] Bid listener on 0.0.0.0:{BID_PORT} (unicast bids)")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 129 and data[0] == 0x02:
            _handle_bid(data, addr)


def _handle_beacon(data: bytes, addr):
    pubkey_bytes = data[1:65]
    sig          = data[65:129]
    signed_region = data[0:65]

    if not _verify(signed_region, sig, pubkey_bytes):
        print(f"[UDP] Beacon from {addr[0]} FAILED signature — dropping")
        return

    pub_hex = pubkey_bytes.hex()
    with state.registry_lock:
        is_new = pub_hex not in state.registry
        state.registry[pub_hex] = {"ip": addr[0], "last_seen": time.time()}

    if is_new:
        print(f"[UDP] ✓ Registered auditor {addr[0]}  pubkey={pub_hex[:12]}...")
   # else:
    #    print(f"[UDP] ↻ Refreshed auditor {addr[0]}  pubkey={pub_hex[:12]}...")


def _handle_bid(data: bytes, addr):
    if not state.collecting_bids:
        return

    pubkey_bytes  = data[1:65]
    sig           = data[65:129]
    signed_region = data[0:65]

    if not _verify(signed_region, sig, pubkey_bytes):
        print(f"[UDP] Bid from {addr[0]} FAILED signature — dropping")
        return

    pub_hex = pubkey_bytes.hex()

    # Only accept bids from registered auditors
    with state.registry_lock:
        if pub_hex not in state.registry:
            print(f"[UDP] Bid from unknown pubkey {pub_hex[:12]}... — dropping")
            return

    with state.bids_lock:
        if any(b["pubkey_hex"] == pub_hex for b in state.bids):
            return  # duplicate bid
        state.bids.append({"pubkey_hex": pub_hex, "ip": addr[0]})

    print(f"[UDP] ✓ Bid received from {addr[0]}  pubkey={pub_hex[:12]}...")


# ── Flow quorum selection ─────────────────────────────────────────────────────

def _query_flow_stake_reputation(pubkey_hex: str) -> tuple[float, float]:
    """
    Query SwarmVerifierV2 on Flow testnet for a node's stake and reputation.
    Returns (stake, reputation). Falls back to (0.0, 0.0) on any error.

    Flow REST API: POST /v1/scripts with a Cadence script body.
    The script returns a JSON-encoded struct; we extract stake and reputation.
    """
    if not FLOW_ENABLED:
        return (0.0, 0.0)

    script = f"""
import {FLOW_CONTRACT_NAME} from {FLOW_CONTRACT_ADDR}

access(all) fun main(pubkey: String): [Fix64?] {{
    let stake = {FLOW_CONTRACT_NAME}.getStake(nodeId: pubkey)
    let rep   = {FLOW_CONTRACT_NAME}.getReputation(nodeId: pubkey)
    return [stake != nil ? Fix64(stake!) : nil, rep]
}}
""".strip()

    import base64
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
            print(f"[Flow] Script query failed: {resp.status_code}")
            return (0.0, 0.0)

        # Flow returns base64-encoded Cadence JSON
        result_bytes = base64.b64decode(resp.json().get("value", ""))
        result       = json.loads(result_bytes)

        # result is an Array of two Optional Fix64 values
        values = result.get("value", [])
        stake  = float(values[0]["value"]["value"]) if values[0]["value"] else 0.0
        rep    = float(values[1]["value"]["value"]) if values[1]["value"] else 0.0
        return (stake, rep)

    except Exception as e:
        print(f"[Flow] Query error for {pubkey_hex[:12]}...: {e}")
        return (0.0, 0.0)


def _select_quorum(bids: list[dict]) -> list[dict]:
    """
    Rank bidding auditors by Flow stake (primary) then reputation (secondary).
    Returns top QUORUM_SIZE entries.

    If FLOW_ENABLED is False, falls back to accepting all bidders (local testing).
    """
    if not FLOW_ENABLED:
        return bids  # no ranking in local test mode

    print(f"[Quorum] Querying Flow for stake/reputation of {len(bids)} bidder(s)...")
    ranked = []
    for b in bids:
        stake, rep = _query_flow_stake_reputation(b["pubkey_hex"])
        if stake == 0.0:
            print(f"[Quorum] {b['pubkey_hex'][:12]}... not registered on Flow — excluded")
            continue
        ranked.append({**b, "stake": stake, "reputation": rep})
        print(f"[Quorum]   {b['pubkey_hex'][:12]}...  stake={stake:.2f}  rep={rep:.4f}")

    ranked.sort(key=lambda x: (x["stake"], x["reputation"]), reverse=True)
    return ranked[:QUORUM_SIZE]


# ── Anomaly trigger ────────────────────────────────────────────────────────────

def trigger_anomaly():
    """
    Broadcasts a signed anomaly packet, waits BID_WINDOW_S for bids,
    then selects the full quorum (all valid bidders for testing).
    Arms the HTTP server and waits for verdicts.
    """
    # Generate fresh CSV for this anomaly event
    state.csv_data           = _generate_drop_csv()
    state.anomaly_confidence = round(float(np.random.uniform(0.87, 0.99)), 4)
    state.bids.clear()
    state.verdicts.clear()
    state.collecting_bids    = True

    packet = state.build_anomaly_packet()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))

    print(f"\n[Anomaly] Broadcast 133-byte anomaly | confidence={state.anomaly_confidence:.4f}")
    print(f"[Anomaly] Collecting bids for {BID_WINDOW_S}s...")

    time.sleep(BID_WINDOW_S)
    state.collecting_bids = False

    with state.bids_lock:
        all_bids = list(state.bids)

    if not all_bids:
        print("[Anomaly] No bids received — returning to IDLE\n")
        return

    # Rank by Flow stake + reputation; falls back to all bidders if FLOW_ENABLED=False
    quorum_list = _select_quorum(all_bids)

    if not quorum_list:
        print("[Anomaly] No eligible quorum members after Flow check — returning to IDLE\n")
        return

    state.quorum            = {b["pubkey_hex"] for b in quorum_list}
    state.expected_verdicts = len(state.quorum)

    src = "Flow-ranked" if FLOW_ENABLED else "local (Flow disabled)"
    print(f"[Anomaly] Quorum selected ({src}): {len(state.quorum)} auditor(s)")
    for b in quorum_list:
        stake_str = f"  stake={b.get('stake', '?'):.2f}  rep={b.get('reputation', '?'):.4f}" if FLOW_ENABLED else ""
        print(f"           {b['ip']}  pubkey={b['pubkey_hex'][:12]}...{stake_str}")

    print(f"[Anomaly] HTTP server armed. Waiting up to {VERDICT_TIMEOUT_S}s for verdicts...")

    # Wait for all verdicts or timeout
    deadline = time.time() + VERDICT_TIMEOUT_S
    while time.time() < deadline:
        with state.verdicts_lock:
            if len(state.verdicts) >= state.expected_verdicts:
                break
        time.sleep(0.5)
    else:
        with state.verdicts_lock:
            received = len(state.verdicts)
        print(f"[Anomaly] Verdict timeout — got {received}/{state.expected_verdicts}")
        if received > 0:
            _run_consensus()

    # Reset for next event — clear nonces too so stale HTTP requests from this
    # cycle cannot be replayed into the next one.
    state.quorum.clear()
    with state.nonces_lock:
        state.nonces.clear()
    state.collecting_verdicts = False
    print("[Anomaly] Returning to IDLE\n")


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
                print("[!] No auditors registered yet. Wait for beacon(s).")
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
    # Separate threads for multicast beacons and unicast bids
    threading.Thread(target=multicast_listener, daemon=True).start()
    threading.Thread(target=bid_listener,       daemon=True).start()

    # HTTP server thread
    server = HTTPServer(("0.0.0.0", HTTP_PORT), TransporterHTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[HTTP] Server listening on 0.0.0.0:{HTTP_PORT}")

    cli()