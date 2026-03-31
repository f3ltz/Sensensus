import hashlib
from typing import Optional
from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigencode_string
from flow_py_sdk.signer import Signer as FlowSigner

def verdict_canonical(pub_hex: str, verdict_bool: bool, confidence: float) -> bytes:
    """
    Canonical string the auditor signs. Must match Pico's C-side reconstruction.
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

def sign_data(sk: SigningKey, data: bytes) -> bytes:
    """ECDSA-P256/SHA-256 — matches Pico's crypto_sign() which uses SHA-256."""
    return sk.sign(data, hashfunc=hashlib.sha256)

def verify_signature(payload: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
    """Verify ECDSA-P256/SHA-256 signature."""
    try:
        vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
        return vk.verify(sig, payload, hashfunc=hashlib.sha256)
    except (BadSignatureError, Exception):
        return False