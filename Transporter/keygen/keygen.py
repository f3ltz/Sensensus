# gen_pico_key.py — run once, save the output
from ecdsa import NIST256p, SigningKey

sk = SigningKey.generate(curve=NIST256p)
print("Private key (hex):", sk.to_string().hex())
print("Public key (hex):",  sk.verifying_key.to_string().hex())

with open("pico_identity.pem", "wb") as f:
    f.write(sk.to_pem())