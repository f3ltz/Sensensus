"""
SwarmVerifier — Auditor Node
Architecture: PL_Genesis Hackathon 2026

Flow:
  1. Broadcast signed beacon every 5 s (PKT_BEACON 0x01, 129 bytes)
  2. Receive PKT_ANOMALY (0x03, 133 bytes)
       → Verify transporter signature
       → Store transporter pubkey + IP
       → Send signed bid (PKT_BID 0x02, 137 bytes) to BID_PORT
  3. Wait for PKT_QUORUM (0x04, 129 bytes) directed unicast on MULTICAST_PORT
       → Verify sig with stored transporter pubkey
       → Confirm bytes 1-64 == own pubkey
       → Proceed to x402 only after this confirmation
  4. x402 flow:
       GET  /data?pubkey=<hex>  →  402 + nonce
       POST /pay  {pubkey, signature}  →  200 {csv, payload}
  5. Run Random Forest on last 50 rows of CSV (data_window[-50:])
  6. Submit signed verdict to Flow contract:
       {auditor_pubkey, verdict, verdict_confidence, csv_cid="", payload_signature}

Storacha upload is NOT the auditor's responsibility.
The transporter uploads the CSV after the Flow contract reaches consensus and
notifies it. The CID is therefore unknown at verdict time — auditors always
submit csv_cid="" and the contract fills it in post-settlement.

Packet formats:
  Beacon  (0x01, 129 bytes): [type 1B][pubkey 64B][sig 64B]
  Bid     (0x02, 137 bytes): [type 1B][pubkey 64B][price float64 LE 8B][sig 64B]
  Anomaly (0x03, 133 bytes): [type 1B][pubkey 64B][conf float32 LE 4B][sig 64B]
  Quorum  (0x04, 129 bytes): [type 1B][nominated_pubkey 64B][sig 64B]

Verdict canonical string (signed by auditor):
  "<128-hex-pubkey>:<0 or 1>:<confidence:.4f>"
  e.g. "abcd1234...ef01:1:0.9412"
  int() cast on verdict is mandatory — Python bool serialises as 'True', not '1'.
"""

import argparse
import hashlib
import io
import os
import socket
import struct
import threading
import time

import joblib
import numpy as np
import pandas as pd
import requests
from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey

# ── Column names (must match Pico's imu_buildCsvBuffer() exactly) ─────────────
CSV_COLUMNS  = ['timestamp_ms', 'ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']
FEATURE_COLS = ['ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']

# ── Sizes (must match config.h) ───────────────────────────────────────────────
CSV_BUFFER_SAMPLES = 75    # rows served by Pico over x402
WINDOW_SIZE        = 50    # rows fed into Random Forest (last 50)
INPUT_TENSOR_SIZE  = 350   # 50 × 7

# ── Network constants (must match config.h) ───────────────────────────────────
MULTICAST_GROUP = '239.0.0.1'
MULTICAST_PORT  = 5005      # beacons, anomaly broadcasts, and directed quorum unicasts
BID_PORT        = 5006      # transporter unicast bid listener (separate socket on Pico)
HTTP_PORT       = 8080

# ── Timeouts ──────────────────────────────────────────────────────────────────
QUORUM_WAIT_S   = 30.0   # how long to wait for PKT_QUORUM after sending a bid
DELIVERY_WAIT_S = 15.0   # x402 HTTP request timeout
VERDICT_WAIT_S  = 10.0   # Flow submission timeout

# ── Flow contract (set via --flow-url and --flow-contract, or env vars) ───────
FLOW_API_URL_DEFAULT      = "http://localhost:8080"   # mock_transporter for demo
FLOW_CONTRACT_ADDR_DEFAULT = ""                        # Flow testnet addr when live

# ── Verdict canonical format ──────────────────────────────────────────────────
def _verdict_canonical(pub_hex: str, verdict_bool: bool, confidence: float) -> bytes:
    """
    Canonical string that the auditor signs and the Flow contract records.
    int() cast is mandatory: bool(True) → 'True', int(True) → '1'.
    The Pico C-side must reconstruct this exact byte string using int(verdict) and %.4f.
    """
    return f"{pub_hex}:{int(verdict_bool)}:{confidence:.4f}".encode()

# ─────────────────────────────────────────────────────────────────────────────
class AuditorNode:
    def __init__(
        self,
        key_path:          str   = "./identity.pem",
        bid_price:         float = 1.0,
        flow_api_url:      str   = FLOW_API_URL_DEFAULT,
        flow_contract_addr: str  = FLOW_CONTRACT_ADDR_DEFAULT,
        flow_enabled:      bool  = False,
    ):
        # ── Cryptographic identity ────────────────────────────────────────────
        self.sk, self.vk = self._load_or_generate_keypair(key_path)
        self.pub_bytes   = self.vk.to_string()   # 64 bytes: X‖Y, no 0x04 prefix
        self.pub_hex     = self.pub_bytes.hex()  # 128 hex chars

        # ── Quorum and bid config ─────────────────────────────────────────────
        self.bid_price    = float(bid_price)   # FLOW tokens offered per verification

        # ── Flow config ───────────────────────────────────────────────────────
        self.flow_api_url       = flow_api_url.rstrip('/')
        self.flow_contract_addr = flow_contract_addr
        self.flow_enabled       = flow_enabled

        # ── Per-event state (reset at the start of each anomaly cycle) ────────
        # Protected by _state_lock; touched by beacon, anomaly, and quorum threads.
        self._state_lock         = threading.Lock()
        self._transporter_pubkey = None   # bytes[64] — set on PKT_ANOMALY receipt
        self._transporter_ip     = None   # str       — set on PKT_ANOMALY receipt
        self._quorum_event       = threading.Event()  # set when PKT_QUORUM confirmed

        # ── Random Forest model (Model B) ─────────────────────────────────────
        print("[*] Loading Random Forest model (Model B)...")
        try:
            self.model = joblib.load('./models/auditor_model.joblib')
            print("[*] Model loaded.")
        except FileNotFoundError:
            print("[WARN] ./models/auditor_model.joblib not found — ML verification skipped.")
            self.model = None

        print(f"[*] Auditor ready. pubkey={self.pub_hex[:16]}...")
        print(f"[*] Bid price:   {self.bid_price} FLOW")
        print(f"[*] Flow submit: {'ENABLED → ' + self.flow_api_url if self.flow_enabled else 'DISABLED (mock /verdict)'}")

    # ── Crypto helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _load_or_generate_keypair(key_path: str):
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                sk = SigningKey.from_pem(f.read())
            print(f"[*] Loaded existing identity from {key_path}")
        else:
            sk = SigningKey.generate(curve=NIST256p)
            with open(key_path, "wb") as f:
                f.write(sk.to_pem())
            print(f"[*] Generated new identity, saved to {key_path}")
        return sk, sk.verifying_key

    def _sign(self, data: bytes) -> bytes:
        """Sign raw bytes with ECDSA-P256/SHA-256, matching Pico's signPayload()."""
        return self.sk.sign(data, hashfunc=hashlib.sha256)

    @staticmethod
    def _verify(payload_bytes: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
        """Verify an ECDSA-P256/SHA-256 signature. Returns False rather than raising."""
        try:
            vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
            vk.verify(sig, payload_bytes, hashfunc=hashlib.sha256)
            return True
        except (BadSignatureError, Exception):
            return False

    # ── Beacon thread (every 5 s) ─────────────────────────────────────────────

    def broadcast_presence(self):
        """
        PKT_BEACON (0x01, 129 bytes):
          byte  0     : 0x01
          bytes 1-64  : auditor pubkey
          bytes 65-128: ECDSA sig over bytes 0-64
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        while True:
            header = struct.pack('<B', 0x01) + self.pub_bytes        # 65 bytes
            packet = header + self._sign(header)                      # 65+64 = 129 bytes
            assert len(packet) == 129, f"Beacon size mismatch: {len(packet)}"
            sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
            print("[Beacon] Sent 129-byte beacon.")
            time.sleep(5)

    # ── Main listener thread: handles PKT_ANOMALY (0x03) and PKT_QUORUM (0x04) ─

    def listen(self):
        """
        Single multicast socket on MULTICAST_PORT receives:
          - PKT_ANOMALY (0x03, 133 bytes) — broadcast from transporter
          - PKT_QUORUM  (0x04, 129 bytes) — directed unicast from transporter to own IP

        The socket is bound to ('', MULTICAST_PORT) so it receives both multicast
        and unicast packets on that port.
        SO_REUSEPORT is required so multiple auditor processes on the same host
        can each receive the same multicast packets independently.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('', MULTICAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print(f"[*] Listening on {MULTICAST_GROUP}:{MULTICAST_PORT}")

        while True:
            data, addr = sock.recvfrom(1024)
            if not data:
                continue
            pkt_type = data[0]
            if pkt_type == 0x03 and len(data) == 133:
                self._handle_anomaly(data, addr)
            elif pkt_type == 0x04 and len(data) == 129:
                self._handle_quorum(data, addr)
            # 0x01 (our own beacon echo) and 0x02 (bids) are ignored here

    # ── PKT_ANOMALY handler ───────────────────────────────────────────────────

    def _handle_anomaly(self, data: bytes, addr):
        """
        PKT_ANOMALY (0x03, 133 bytes):
          byte  0     : 0x03
          bytes 1-64  : transporter pubkey
          bytes 65-68 : confidence float32 LE
          bytes 69-132: ECDSA sig over bytes 0-68
        """
        transporter_pubkey = data[1:65]
        confidence         = struct.unpack('<f', data[65:69])[0]
        sig                = data[69:133]
        signed_region      = data[0:69]

        if not self._verify(signed_region, sig, transporter_pubkey):
            print(f"[WARN] Anomaly from {addr[0]} — bad signature. Dropping.")
            return

        print(f"\n[Anomaly] Verified | transporter={addr[0]} | confidence={confidence:.4f}")

        # Store per-event state and reset the quorum gate
        with self._state_lock:
            self._transporter_pubkey = bytes(transporter_pubkey)
            self._transporter_ip     = addr[0]
            self._quorum_event.clear()

        self._send_bid(addr[0])

        # Start a quorum wait thread so the main listener is never blocked
        threading.Thread(
            target=self._wait_for_quorum_then_fetch,
            daemon=True,
        ).start()

    def _send_bid(self, transporter_ip: str):
        """
        PKT_BID (0x02, 137 bytes):
          byte  0     : 0x02
          bytes 1-64  : auditor pubkey
          bytes 65-72 : bid price float64 LE   ← new field vs old 129-byte format
          bytes 73-136: ECDSA sig over bytes 0-72

        Sent unicast to BID_PORT (5006) — the transporter's dedicated bid listener.
        A separate socket avoids the multicast socket silently dropping unicast
        packets on some Linux/lwIP configurations.
        """
        header     = struct.pack('<B', 0x02) + self.pub_bytes       # 65 bytes
        price_bytes = struct.pack('<d', self.bid_price)              # 8 bytes float64 LE
        to_sign    = header + price_bytes                            # 73 bytes
        packet     = to_sign + self._sign(to_sign)                  # 73+64 = 137 bytes
        assert len(packet) == 137, f"Bid size mismatch: {len(packet)}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (transporter_ip, BID_PORT))
        sock.close()
        print(f"[Bid] Sent 137-byte bid to {transporter_ip}:{BID_PORT} | price={self.bid_price} FLOW")

    # ── PKT_QUORUM handler ────────────────────────────────────────────────────

    def _handle_quorum(self, data: bytes, addr):
        """
        PKT_QUORUM (0x04, 129 bytes):
          byte  0     : 0x04
          bytes 1-64  : nominated auditor pubkey  ← who this is addressed to
          bytes 65-128: ECDSA sig over bytes 0-64, signed by TRANSPORTER

        Verification steps (both must pass):
          1. Sig is valid using the stored transporter pubkey
          2. bytes 1-64 == own pubkey (packet is addressed to us)
        """
        nominated_pubkey = data[1:65]
        sig              = data[65:129]
        signed_region    = data[0:65]

        with self._state_lock:
            transporter_pub = self._transporter_pubkey

        if transporter_pub is None:
            print(f"[Quorum] Received PKT_QUORUM from {addr[0]} but no active anomaly. Ignoring.")
            return

        # Step 1: verify sig with transporter's pubkey
        if not self._verify(signed_region, sig, transporter_pub):
            print(f"[Quorum] Bad transporter signature from {addr[0]}. Dropping.")
            return

        # Step 2: confirm the packet is addressed to us
        if nominated_pubkey != self.pub_bytes:
            # This packet is a quorum notification for a different auditor — ignore quietly
            return

        print(f"[Quorum] ✓ Selected for quorum by {addr[0]}")
        self._quorum_event.set()

    def _wait_for_quorum_then_fetch(self):
        """
        Waits up to QUORUM_WAIT_S for a confirmed quorum notification.
        If confirmed: executes the x402 fetch flow.
        If timeout: stands down cleanly.
        """
        confirmed = self._quorum_event.wait(timeout=QUORUM_WAIT_S)
        if not confirmed:
            print("[Quorum] Timeout — not selected for quorum or notification lost. Standing down.")
            return

        with self._state_lock:
            transporter_ip = self._transporter_ip

        if not transporter_ip:
            print("[Quorum] No transporter IP recorded. Cannot proceed.")
            return

        self._execute_x402_fetch(transporter_ip)

    # ── x402 HTTP flow ────────────────────────────────────────────────────────

    def _execute_x402_fetch(self, transporter_ip: str):
        """
        GET  /data?pubkey=<hex>
          → 402 + {nonce}   : proceed
          → 403             : not in quorum (should not happen after PKT_QUORUM, but handle it)
          → other           : log and abort

        POST /pay  {pubkey, signature_over_nonce}
          → 200 + {csv, payload}   : run verification
          → other                  : log and abort

        The payload field from the 200 response contains:
          {transporter_pubkey, auditor_pubkey, anomaly_confidence,
           timestamp_ms, cid, payload_signature}
        payload_signature is carried through to the verdict body — it ties the
        auditor's verdict to this specific anomaly event on-chain.
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
                try:
                    reason = resp.json().get("error", "no detail")
                except Exception:
                    reason = "no detail"
                print(f"[x402] 403 — {reason}. Standing down.")
                return

            if resp.status_code != 402:
                print(f"[x402] Unexpected status on GET /data: {resp.status_code}. Aborting.")
                return

            payment_info = resp.json()
            nonce_hex    = payment_info.get("nonce", "")
            if not nonce_hex:
                print("[x402] 402 response missing nonce. Aborting.")
                return

            print(f"[x402] 402 received. nonce={nonce_hex[:16]}...")

            # ── Step 2: POST /pay ─────────────────────────────────────────────
            nonce_bytes = bytes.fromhex(nonce_hex)
            sig_hex     = self._sign(nonce_bytes).hex()

            pay_resp = requests.post(
                f"{base_url}/pay",
                json={"pubkey": self.pub_hex, "signature": sig_hex},
                timeout=DELIVERY_WAIT_S,
            )

            if pay_resp.status_code != 200:
                print(f"[x402] POST /pay rejected: {pay_resp.status_code}. Aborting.")
                return

            print("[x402] ✓ Data access granted.")
            response_body = pay_resp.json()
            csv_data      = response_body.get("csv", "")
            payload       = response_body.get("payload", {})

            if not csv_data:
                print("[x402] 200 response missing csv field. Aborting.")
                return
            if not payload:
                print("[x402] 200 response missing payload field. Aborting.")
                return

            # payload_signature ties this verdict to the specific anomaly event on-chain
            payload_signature = payload.get("payload_signature", "")

            if not payload_signature:
                print("[x402] payload.payload_signature missing — verdict chain broken. Aborting.")
                return

            self._run_verification(csv_data, payload_signature)

        except requests.exceptions.RequestException as e:
            print(f"[x402] Network error: {e}")

    # ── ML verification ───────────────────────────────────────────────────────

    def _run_verification(self, csv_data: str, payload_signature: str):
        """
        1. Parse CSV — validate column names at runtime (catches training/serving mismatch)
        2. Take data_window[-50:] — the drop is at the tail of the 75-row buffer
        3. Flatten to (1, 350) — must match INPUT_TENSOR_SIZE = 50 × 7
        4. Run Random Forest predict() + predict_proba()
        5. Submit signed verdict to Flow contract (csv_cid always "")
        """
        if self.model is None:
            print("[ML] No model loaded — cannot produce verdict.")
            return

        try:
            df = pd.read_csv(io.StringIO(csv_data), names=CSV_COLUMNS, header=0)

            # Validate columns at runtime — catches a training/serving column order mismatch
            missing = [c for c in FEATURE_COLS if c not in df.columns]
            if missing:
                print(f"[ML] CSV missing columns: {missing}. Got: {list(df.columns)}. Aborting.")
                return

            data_window = df[FEATURE_COLS].values   # shape (≤75, 7)

            # Take LAST 50 rows — the drop event is at the tail, not the head
            if len(data_window) >= WINDOW_SIZE:
                data_window = data_window[-WINDOW_SIZE:]
            else:
                # Fewer rows than expected — zero-pad at the front
                print(f"[ML] Only {len(data_window)} rows, padding to {WINDOW_SIZE}.")
                padding     = np.zeros((WINDOW_SIZE - len(data_window), len(FEATURE_COLS)))
                data_window = np.vstack((padding, data_window))

            flattened     = data_window.flatten().reshape(1, -1)   # (1, 350)
            assert flattened.shape == (1, INPUT_TENSOR_SIZE), \
                f"Shape mismatch: {flattened.shape} expected (1, {INPUT_TENSOR_SIZE})"

            prediction    = self.model.predict(flattened)[0]
            probabilities = self.model.predict_proba(flattened)[0]
            confidence    = float(max(probabilities))
            verdict_bool  = bool(prediction == 1)

            print(f"[ML] Verdict: {'DROP' if verdict_bool else 'NORMAL'} | confidence={confidence:.4f}")

            # csv_cid is always "" at verdict time.
            # reaches consensus and notifies it — the CID does not exist yet.
            self._submit_verdict(verdict_bool, confidence, payload_signature)

        except AssertionError as e:
            print(f"[ML] Assertion failed: {e}")
        except Exception as e:
            print(f"[ML] Unexpected error: {e}")

        # ── Verdict submission ────────────────────────────────────────────────────

    def _submit_verdict(
        self,
        verdict_bool:      bool,
        confidence:        float,
        payload_signature: str,
    ):
        """
        Verdict body (posted to Flow contract):
          {
            auditor_pubkey,       ← 128 hex chars
            verdict,              ← bool
            verdict_confidence,   ← float
            csv_cid,              ← always "" (transporter uploads after consensus)
            payload_signature,    ← ties verdict to specific anomaly event
          }

        verdict_sig covers the canonical string:
          "<pubkey>:<0 or 1>:<confidence:.4f>"

        When flow_enabled=True : POST to Flow contract REST API
        When flow_enabled=False: POST to mock_transporter /verdict (demo/dev mode)
        """
        canonical  = _verdict_canonical(self.pub_hex, verdict_bool, confidence)
        sig_hex    = self._sign(canonical).hex()

        body = {
            "auditor_pubkey":       self.pub_hex,
            "verdict":              verdict_bool,
            "verdict_confidence":   confidence,
            "csv_cid":              "",  # transporter fills this post-consensus
            "payload_signature":    payload_signature,
            "verdict_signature":    sig_hex,
        }

        if self.flow_enabled:
            self._submit_to_flow(body)
        else:
            self._submit_to_mock(body)

    def _submit_to_flow(self, body: dict):
        """
        Submit verdict as a Flow transaction to the SwarmVerifierV2 contract.
        Flow testnet REST endpoint: https://rest-testnet.onflow.org/v1/transactions

        For the hackathon demo this posts to the configured flow_api_url.
        In production: construct a proper Cadence transaction with the auditor's
        ECDSA key as the Flow account key.
        """
        url = f"{self.flow_api_url}/verdict"
        print(f"[Flow] Submitting verdict to {url} ...")
        try:
            resp = requests.post(url, json=body, timeout=VERDICT_WAIT_S)
            if resp.status_code in (200, 201):
                print(f"[Flow] ✓ Verdict accepted. Response: {resp.status_code}")
            else:
                print(f"[Flow] ✗ Verdict rejected: {resp.status_code} — {resp.text[:120]}")
        except Exception as e:
            print(f"[Flow] Submission error: {e}")

    def _submit_to_mock(self, body: dict):
        """
        In demo/dev mode, submit to the mock_transporter's /verdict endpoint.
        This updates the dashboard and triggers simulated on-chain consensus.
        Remove this method once SwarmVerifierV2 is live on Flow Testnet.
        """
        with self._state_lock:
            transporter_ip = self._transporter_ip

        if not transporter_ip:
            print("[Verdict] No transporter IP — cannot submit.")
            return

        url = f"http://{transporter_ip}:{HTTP_PORT}/verdict"
        print(f"[Verdict] Submitting to mock transporter at {url} ...")
        try:
            resp = requests.post(url, json=body, timeout=VERDICT_WAIT_S)
            print(f"[Verdict] Response: {resp.status_code}")
        except Exception as e:
            print(f"[Verdict] Submission error: {e}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SwarmVerifier — Auditor Node",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--key-file",
        default="./identity.pem",
        help="Path to PEM file for persistent ECDSA identity. "
             "Generated on first run if absent. "
             "Run multiple auditors with different files: "
             "--key-file ./identity_2.pem",
    )
    parser.add_argument(
        "--bid-price",
        type=float,
        default=1.0,
        help="Bid price in FLOW tokens per verification job. "
             "Lower bids rank higher in quorum selection "
             "(combined with reputation and stake weighting).",
    )
    parser.add_argument(
        "--flow-url",
        default=os.environ.get("FLOW_API_URL", FLOW_API_URL_DEFAULT),
        help="Flow contract REST API URL. Defaults to mock_transporter on localhost. "
             "Set to https://rest-testnet.onflow.org for live testnet. "
             "Can also be set via FLOW_API_URL env var.",
    )
    parser.add_argument(
        "--flow-contract",
        default=os.environ.get("FLOW_CONTRACT_ADDR", FLOW_CONTRACT_ADDR_DEFAULT),
        help="SwarmVerifierV2 contract address on Flow Testnet. "
             "Can also be set via FLOW_CONTRACT_ADDR env var.",
    )
    parser.add_argument(
        "--flow-enabled",
        action="store_true",
        default=False,
        help="Submit verdicts to the Flow contract REST API instead of mock_transporter. "
             "Requires --flow-url and --flow-contract to be set correctly.",
    )
    args = parser.parse_args()

    if args.flow_enabled and not args.flow_contract:
        print("[WARN] --flow-enabled set but --flow-contract is empty. "
              "Verdict submissions may fail.")

    node = AuditorNode(
        key_path           = args.key_file,
        bid_price          = args.bid_price,
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