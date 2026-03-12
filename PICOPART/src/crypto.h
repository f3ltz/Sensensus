#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

// Call once at startup. Uses RP2350 hardware TRNG.
void     crypto_init();

// Generate a fresh P-256 keypair. priv=32B, pub=64B (X||Y, no 0x04 prefix).
bool     crypto_keygen(uint8_t *priv_out, uint8_t *pub_out);

// ECDSA-P256/SHA-256. sig must be 64 bytes. Returns true on success.
bool     crypto_sign  (const uint8_t *priv, const uint8_t *msg, size_t msg_len,
                       uint8_t *sig_out);

// Verify an ECDSA-P256/SHA-256 signature. Returns true if valid.
bool     crypto_verify(const uint8_t *pub,  const uint8_t *msg, size_t msg_len,
                       const uint8_t *sig);

// Hex encode/decode helpers
void     bytes_to_hex(const uint8_t *in, size_t len, char *out);
bool     hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out);

#ifdef __cplusplus
}
#endif