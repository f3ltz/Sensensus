import hashlib

from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigencode_string
from flow_py_sdk.signer import Signer as FlowSigner

# ── Cryptography Helpers ──────────────────────────────────────────────────────

class _EcdsaSigner(FlowSigner):
    """Flow SDK signer that uses SHA3-256 (required by Flow protocol)."""
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

def _sign(sk, data: bytes) -> bytes:
    """ECDSA-P256/SHA-256 signature generator."""
    return sk.sign(data, hashfunc=hashlib.sha256)

def _verify(payload: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
    """Verify ECDSA-P256/SHA-256 signature."""
    try:
        vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
        vk.verify(sig, payload, hashfunc=hashlib.sha256)
        return True
    except (BadSignatureError, Exception):
        return False