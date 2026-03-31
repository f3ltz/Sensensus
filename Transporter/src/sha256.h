/*  Brad Conte's SHA-256 — public domain, no dependencies  */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_init  (SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final (SHA256_CTX *ctx, uint8_t *hash);
void sha256_bytes (const uint8_t *data, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif 