import json
import os
import struct
import threading
import time

from ecdsa import NIST256p, SigningKey
from mock.crypto import _sign

# ── Global State Management ───────────────────────────────────────────────────

class TransporterState:
    """Centralized state manager for the mock transporter."""
    def __init__(self):
        # ── Cryptographic identity ────────────────────────────────────────────
        self.sk, self.vk = self._load_or_generate_keypair("../Identities/transporter_identity.pem")
        self.pub_bytes   = self.vk.to_string()
        self.pub_hex     = self.pub_bytes.hex()

        # ── Network & Registry State ──────────────────────────────────────────
        self.registry      = {}
        self.registry_lock = threading.Lock()

        self.bids            = {}
        self.bids_lock       = threading.Lock()
        self.collecting_bids = False

        self.quorum = {}

        # ── Data Delivery State ───────────────────────────────────────────────
        self.nonces      = {}
        self.nonces_lock = threading.Lock()

        self.issued_payload_sigs      = {}
        self.issued_payload_sigs_lock = threading.Lock()

        # ── Per-Event State ───────────────────────────────────────────────────
        self.current_event_id:   str   = ""
        self.anomaly_confidence: float = 0.93
        self.csv_data:           str   = ""

        self.verdicts          = {}
        self.verdicts_lock     = threading.Lock()
        self.expected_verdicts = 0

        # Flow blockchain synchronization event
        self.register_sealed = threading.Event()
        self.register_sealed.set()

        # ── Lifecycle & Monitoring ────────────────────────────────────────────
        self.system_status  = "IDLE"
        self.settled_events = []
        self.events_lock    = threading.Lock()
        self.last_quat      = {"qw": 1.0, "qx": 0.0, "qy": 0.0, "qz": 0.0}

        print(f"[Transporter] pubkey={self.pub_hex[:16]}...")

    @staticmethod
    def _load_or_generate_keypair(key_path: str):
        """Loads existing identity or generates a new one."""
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

    # ── Packet Building Helpers ───────────────────────────────────────────────

    def build_anomaly_packet(self) -> bytes:
        header     = struct.pack('<B', 0x03)
        conf_bytes = struct.pack('<f', self.anomaly_confidence)
        to_sign    = header + self.pub_bytes + conf_bytes
        sig        = _sign(self.sk, to_sign)
        packet     = to_sign + sig
        assert len(packet) == 133
        return packet

    def build_quorum_packet(self, auditor_pubkey_bytes: bytes) -> bytes:
        header = struct.pack('<B', 0x04) + auditor_pubkey_bytes
        sig    = _sign(self.sk, header)
        packet = header + sig
        assert len(packet) == 129
        return packet

    def build_submission_sig(self, quorum_ids: list) -> str:
        canonical = json.dumps({
            "transporter_pubkey": self.pub_hex,
            "anomaly_confidence": self.anomaly_confidence,
            "timestamp_ms":       int(time.time() * 1000),
            "quorum_ids":         sorted(quorum_ids),
        }, separators=(',', ':')).encode()
        return _sign(self.sk, canonical).hex()

    def build_payload_json(self, auditor_pubkey_hex: str) -> dict:
        timestamp_ms = int(time.time() * 1000)
        canonical_str = (
            f'{{"anomaly_confidence":{self.anomaly_confidence:.4f},'
            f'"auditor_pubkey":"{auditor_pubkey_hex}",'
            f'"event_id":"{self.current_event_id}",'
            f'"timestamp_ms":{timestamp_ms},'
            f'"transporter_pubkey":"{self.pub_hex}"}}'
        )
        sig_hex = _sign(self.sk, canonical_str.encode('utf-8')).hex()

        body = {
            "transporter_pubkey":  self.pub_hex,
            "auditor_pubkey":      auditor_pubkey_hex,
            "anomaly_confidence":  self.anomaly_confidence,
            "timestamp_ms":        timestamp_ms,
            "event_id":            self.current_event_id,
            "payload_signature":   sig_hex,
            "deposit":             0.5,
        }

        with self.issued_payload_sigs_lock:
            self.issued_payload_sigs[auditor_pubkey_hex] = sig_hex

        return body

state = TransporterState()