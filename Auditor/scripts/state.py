import os
import socket
import threading
from typing import Optional
import joblib
import numpy as np
from ecdsa import NIST256p, SigningKey

class LazyDropModel:
    def predict(self, X):
        return np.ones(len(X), dtype=int)

    def predict_proba(self, X):
        p1 = np.random.uniform(0.60, 0.70, size=len(X))
        p0 = 1.0 - p1
        return np.vstack((p0, p1)).T

class AuditorState:
    def __init__(self):
        # ── Cryptographic identity ────────────────────────────────────────────
        self.sk: Optional[SigningKey] = None
        self.vk = None
        self.pub_bytes: bytes = b""
        self.pub_hex: str = ""

        # ── Config ────────────────────────────────────────────────────────────
        self.bid_price: float = 1.0
        self.deposit_amount: float = 0.5
        self.flow_api_url: str = ""
        self.flow_contract_addr: str = ""
        self.flow_enabled: bool = False
        self.port: int = 5005
        self.model = None
        self.unicast_sock: Optional[socket.socket] = None

        # ── Per-event state ───────────────────────────────────────────────────
        self.state_lock = threading.Lock()
        self.transporter_pubkey: Optional[bytes] = None
        self.transporter_ip: Optional[str] = None
        self.current_event_id: Optional[str] = None
        self.quorum_event = threading.Event()

    def initialize(self, key_path, model_path, port, bid_price, deposit, flow_api_url, flow_contract_addr, flow_enabled):
        self.sk, self.vk = self._load_or_generate_keypair(key_path)
        self.pub_bytes = self.vk.to_string()
        self.pub_hex = self.pub_bytes.hex()
        
        self.port = port
        self.bid_price = float(bid_price)
        self.deposit_amount = float(deposit)
        self.flow_api_url = flow_api_url.rstrip('/')
        self.flow_contract_addr = flow_contract_addr
        self.flow_enabled = flow_enabled

        # Set up unicast socket
        self.unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.unicast_sock.bind(('', self.port))
        self.unicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        print("[*] Loading Random Forest model (Model B)...")
        try:
            self.model = joblib.load(model_path)
            print("[*] Model loaded.")
        except FileNotFoundError:
            print("[WARN] Model not found — ML verification skipped.")
            self.model = None

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

state = AuditorState()