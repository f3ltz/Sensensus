import socket
import time
import json
import threading
import requests
import hashlib
import struct
import joblib
import pandas as pd
import numpy as np
import io
from ecdsa import SigningKey, NIST256p, VerifyingKey, BadSignatureError


# ── Column names must match exactly what the Pico serialises in imu_buildCsvBuffer()
# Pico output: "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n"
CSV_COLUMNS   = ['timestamp_ms', 'ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']
FEATURE_COLS  = ['ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']

# ── Window sizes (must match config.h)
CSV_BUFFER_SAMPLES = 75   # rows served by Pico
WINDOW_SIZE        = 50   # rows expected by both models

# ── Network constants (must match config.h)
MULTICAST_GROUP = '239.0.0.1'
MULTICAST_PORT  = 5005      # Pico's net_handleUdp() listens here
HTTP_PORT       = 8080

# ── Verdict canonical format (agreed between Ranjit and Asrith)
# Pico must reconstruct this exact string to verify the auditor signature.
# Format: "<128-hex-pubkey>:<0 or 1>:<confidence 4 d.p.>"
# Example: "abcd...ef:1:0.9412"
def _verdict_canonical(pub_hex: str, verdict_bool: bool, confidence: float) -> bytes:
    return f"{pub_hex}:{int(verdict_bool)}:{confidence:.4f}".encode()


class AuditorNode:
    def __init__(self,
                 multicast_group: str = MULTICAST_GROUP,
                 multicast_port:  int = MULTICAST_PORT):

        # ── Cryptographic identity (NIST P-256 — matches Pico's micro-ecc secp256r1)
        self.sk       = SigningKey.generate(curve=NIST256p)
        self.vk       = self.sk.verifying_key
        self.pub_bytes = self.vk.to_string()   # 64 bytes: X‖Y
        self.pub_hex   = self.pub_bytes.hex()  # 128 hex chars

        self.multicast_group = multicast_group
        self.multicast_port  = multicast_port

        print("[*] Loading Random Forest model (Model B)...")
        try:
            self.model = joblib.load('./models/auditor_model.joblib')
            print("[*] Model loaded.")
        except FileNotFoundError:
            print("[WARN] auditor_model.joblib not found — ML verification will be skipped.")
            self.model = None

        print(f"[*] Auditor ready. pubkey={self.pub_hex[:16]}...")

    # ──────────────────────────────────────────────────────────────────────────
    # Crypto helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _sign(self, data: bytes) -> bytes:
        """Sign raw bytes with SHA-256, matching Ranjit's signPayload() in crypto.cpp."""
        return self.sk.sign(data, hashfunc=hashlib.sha256)

    @staticmethod
    def _verify_pico_signature(payload_bytes: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
        """
        Verify an ECDSA-P256/SHA-256 signature produced by the Pico.
        pubkey_bytes: 64-byte raw X‖Y (uncompressed, no 0x04 prefix).
        Returns False rather than raising on bad sig.
        """
        try:
            vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
            vk.verify(sig, payload_bytes, hashfunc=hashlib.sha256)
            return True
        except (BadSignatureError, Exception):
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # Beacon thread  (every 5 s)
    # ──────────────────────────────────────────────────────────────────────────

    def broadcast_presence(self):
        """
        Beacon format (129 bytes):
          byte  0    : 0x01
          bytes 1-64 : pubkey
          bytes 65-128: ECDSA sig over bytes 0-64
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        while True:
            msg_to_sign = struct.pack('<B', 0x01) + self.pub_bytes
            packet      = msg_to_sign + self._sign(msg_to_sign)
            assert len(packet) == 129, f"Beacon size mismatch: {len(packet)}"

            sock.sendto(packet, (self.multicast_group, self.multicast_port))
            print("[Beacon] Sent 129-byte presence beacon.")
            time.sleep(5)

    # ──────────────────────────────────────────────────────────────────────────
    # Anomaly listener thread
    # ──────────────────────────────────────────────────────────────────────────

    def listen_for_anomalies(self):
        """
        Anomaly broadcast format (133 bytes):
          byte  0     : 0x03
          bytes 1-64  : transporter pubkey
          bytes 65-68 : confidence float32 LE
          bytes 69-132: ECDSA sig over bytes 0-68
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(('', self.multicast_port))
        mreq = struct.pack("4sl", socket.inet_aton(self.multicast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print(f"[*] Listening for anomalies on {self.multicast_group}:{self.multicast_port}")

        while True:
            data, addr = sock.recvfrom(1024)

            if len(data) != 133 or data[0] != 0x03:
                continue

            transporter_pubkey = data[1:65]
            confidence         = struct.unpack('<f', data[65:69])[0]
            sig                = data[69:133]
            signed_region      = data[0:69]   # bytes 0-68 inclusive

            # ── Verify Pico signature before doing anything else
            if not self._verify_pico_signature(signed_region, sig, transporter_pubkey):
                print(f"[WARN] Anomaly from {addr[0]} failed signature check — dropping.")
                continue

            print(f"\n[Alert] Verified anomaly from {addr[0]} | confidence={confidence:.2f}")
            self._send_bid(addr[0])

    # ──────────────────────────────────────────────────────────────────────────
    # Bid
    # ──────────────────────────────────────────────────────────────────────────

    def _send_bid(self, transporter_ip: str):
        """
        Bid format (129 bytes):
          byte  0    : 0x02
          bytes 1-64 : pubkey
          bytes 65-128: ECDSA sig over bytes 0-64

        Sent to MULTICAST_PORT (5005) — the port net_handleUdp() on the Pico
        is actually bound to.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        msg_to_sign = struct.pack('<B', 0x02) + self.pub_bytes
        packet      = msg_to_sign + self._sign(msg_to_sign)
        assert len(packet) == 129, f"Bid size mismatch: {len(packet)}"

        sock.sendto(packet, (transporter_ip, self.multicast_port))
        print(f"[Bid] Sent 129-byte bid to {transporter_ip}:{self.multicast_port}")

        # Wait for Pico's 500 ms quorum collection window to close
        time.sleep(0.6)
        self._execute_x402_purchase(transporter_ip)

    # ──────────────────────────────────────────────────────────────────────────
    # x402 HTTP flow
    # ──────────────────────────────────────────────────────────────────────────

    def _execute_x402_purchase(self, transporter_ip: str):
        """
        Step 1: GET /data
          → 402  : proceed with nonce
          → 403  : not selected for quorum, abort cleanly
          → other: log and abort

        Step 2: POST /pay  { pubkey, signature }
          → 200  : run ML verification
          → other: log and abort
        """
        base_url = f"http://{transporter_ip}:{HTTP_PORT}"

        try:
            # ── Step 1
            resp = requests.get(f"{base_url}/data", timeout=3)

            if resp.status_code == 403:
                print("[x402] Not selected for quorum. Standing down.")
                return

            if resp.status_code != 402:
                print(f"[x402] Unexpected status on GET /data: {resp.status_code}")
                return

            payment_info = resp.json()
            nonce_hex    = payment_info.get("nonce", "")
            if not nonce_hex:
                print("[x402] 402 response missing nonce field.")
                return

            print(f"[x402] 402 received. nonce={nonce_hex}")

            # ── Step 2
            nonce_bytes   = bytes.fromhex(nonce_hex)
            sig_hex       = self._sign(nonce_bytes).hex()
            pay_resp      = requests.post(
                f"{base_url}/pay",
                json={"pubkey": self.pub_hex, "signature": sig_hex},
                timeout=5,
            )

            if pay_resp.status_code != 200:
                print(f"[x402] Payment rejected: {pay_resp.status_code}")
                return

            print("[x402] Payment accepted. Running ML verification...")
            data_json = pay_resp.json()
            csv_data  = data_json.get("csv", "")
            self._run_ml_verification(csv_data, transporter_ip)

        except requests.exceptions.RequestException as e:
            print(f"[Error] Network failure during x402 flow: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # ML verification
    # ──────────────────────────────────────────────────────────────────────────

    def _run_ml_verification(self, csv_data: str, transporter_ip: str):
        if self.model is None:
            print("[ML] No model loaded — cannot produce verdict.")
            return

        try:
            df = pd.read_csv(io.StringIO(csv_data), names=CSV_COLUMNS, header=0)

            # ── Validate columns
            missing = [c for c in FEATURE_COLS if c not in df.columns]
            if missing:
                print(f"[ML] CSV missing expected columns: {missing}. Got: {list(df.columns)}")
                return

            data_window = df[FEATURE_COLS].values  # shape (≤75, 7)

            # ── Take the LAST 50 rows — the drop event is at the end of the buffer
            if len(data_window) >= WINDOW_SIZE:
                data_window = data_window[-WINDOW_SIZE:]
            else:
                # Pad with zeros at the front if somehow fewer rows arrived
                padding     = np.zeros((WINDOW_SIZE - len(data_window), 7))
                data_window = np.vstack((padding, data_window))

            flattened = data_window.flatten().reshape(1, -1)  # (1, 350)

            prediction    = self.model.predict(flattened)[0]
            probabilities = self.model.predict_proba(flattened)[0]
            confidence    = float(max(probabilities))
            verdict_bool  = bool(prediction == 1)

            print(f"[ML] Verdict: {'DROP' if verdict_bool else 'NORMAL'} | confidence={confidence:.4f}")
            self._submit_verdict(transporter_ip, verdict_bool, confidence)

        except Exception as e:
            print(f"[ML] Error during verification: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Verdict submission
    # ──────────────────────────────────────────────────────────────────────────

    def _submit_verdict(self, transporter_ip: str, verdict_bool: bool, confidence: float):
        """
        POST /verdict

        Canonical message signed:
          "<128-hex-pubkey>:<0 or 1>:<confidence 4 d.p.>"
          e.g. "abcd...ef:1:0.9412"

        NOTE: The Pico's verifySignature() in the POST /verdict handler MUST
        reconstruct this exact byte string using int(verdict) and %.4f formatting.
        """
        canonical = _verdict_canonical(self.pub_hex, verdict_bool, confidence)
        sig_hex   = self._sign(canonical).hex()

        payload = {
            "auditor_pubkey":           self.pub_hex,
            "verdict":                  verdict_bool,
            "verdict_confidence":       confidence,
            "auditor_verdict_signature": sig_hex,
        }

        url = f"http://{transporter_ip}:{HTTP_PORT}/verdict"
        print(f"[Verdict] Submitting to {url} ...")
        try:
            res = requests.post(url, json=payload, timeout=3)
            print(f"[Verdict] Response: {res.status_code}")
        except Exception as e:
            print(f"[Error] Failed to submit verdict: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    auditor = AuditorNode()
    threading.Thread(target=auditor.broadcast_presence,  daemon=True).start()
    threading.Thread(target=auditor.listen_for_anomalies, daemon=True).start()
    while True:
        time.sleep(1)