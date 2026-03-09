#pragma once

// ============================================================
//  sha256.h
//  Standalone SHA-256 implementation by Brad Conte.
//  Public domain — no license restrictions.
//  Source: https://github.com/B-Con/crypto-algorithms
//
//  Used here instead of mbedtls because the Arduino-Pico core
//  bundles mbedtls internally for its Wi-Fi stack but does not
//  expose its headers for direct use. This drop-in replacement
//  has zero external dependencies and compiles on any platform.
// ============================================================

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 32  // SHA-256 digest size in bytes

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len);
void sha256_final(SHA256_CTX* ctx, uint8_t hash[SHA256_BLOCK_SIZE]);
