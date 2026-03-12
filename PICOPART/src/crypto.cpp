#include "crypto.h"
#include "sha256.h"
#include <uECC.h>
#include <pico/rand.h>
#include <string.h>
#include <Arduino.h>

// ── RNG for micro-ecc — uses RP2350 hardware TRNG ────────────────────────────
static int _uECC_rng(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; i += 4) {
        uint32_t r = get_rand_32();
        unsigned left = size - i;
        memcpy(dest + i, &r, left < 4 ? left : 4);
    }
    return 1;
}

void crypto_init() {
    uECC_set_rng(_uECC_rng);
}

bool crypto_keygen(uint8_t *priv_out, uint8_t *pub_out) {
    return uECC_make_key(pub_out, priv_out, uECC_secp256r1()) == 1;
}

bool crypto_sign(const uint8_t *priv, const uint8_t *msg, size_t msg_len,
                 uint8_t *sig_out) {
    uint8_t hash[HASH_BYTES];
    sha256_bytes(msg, msg_len, hash);
    return uECC_sign(priv, hash, HASH_BYTES, sig_out, uECC_secp256r1()) == 1;
}

bool crypto_verify(const uint8_t *pub, const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig) {
    uint8_t hash[HASH_BYTES];
    sha256_bytes(msg, msg_len, hash);
    return uECC_verify(pub, hash, HASH_BYTES, sig, uECC_secp256r1()) == 1;
}

void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hx[in[i] >> 4];
        out[i*2+1] = hx[in[i] & 0xf];
    }
    out[len*2] = '\0';
}

bool hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out) {
    if (hex_len % 2 != 0) return false;
    for (size_t i = 0; i < hex_len; i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i]), lo = nibble(hex[i+1]);
        if (hi < 0 || lo < 0) return false;
        out[i/2] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}