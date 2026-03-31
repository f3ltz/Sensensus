import hashlib

from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
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


def _sign(sk, data: bytes) -> bytes:
    return sk.sign(data, hashfunc=hashlib.sha256)


def _verify(payload: bytes, sig: bytes, pubkey_bytes: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey_bytes, curve=NIST256p)
        vk.verify(sig, payload, hashfunc=hashlib.sha256)
        return True
    except (BadSignatureError, Exception):
        return False