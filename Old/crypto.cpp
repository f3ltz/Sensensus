// ============================================================
//  crypto.cpp
//  Implementation of the crypto.h interface using:
//    - micro-ecc  (ECDSA key generation, signing, verification)
//    - mbedtls    (SHA-256 hashing — bundled with the Pico SDK)
//
//  micro-ecc needs a hardware RNG callback registered before it
//  can generate keys. We use the RP2040's ROSC-based hardware
//  RNG for this, accessed through the Pico SDK's get_rand_32().
// ============================================================

#include "crypto.h"
#include <Arduino.h>
#include <string.h>

// micro-ecc
#include "uECC.h"

// Standalone SHA-256 — Brad Conte's public domain implementation.
// Replaces mbedtls which is bundled inside the Arduino-Pico core's
// Wi-Fi stack but does not expose its headers for direct use.
// sha256.h/.c live in src/ alongside this file — no library needed.
#include "sha256.h"

// RP2350 hardware TRNG — provided by the Pico SDK's pico_rand module.
// Exposed by the Arduino-Pico core; no extra lib_dep needed.
#include "pico/rand.h"

// ---- Module-level key storage ----
uint8_t g_publicKey[PUBKEY_SIZE];
uint8_t g_privateKey[PRIVKEY_SIZE];

// ============================================================
//  RNG callback required by micro-ecc
//  The RP2350 has a dedicated hardware True Random Number Generator
//  (TRNG), a significant upgrade from the RP2040's ring-oscillator
//  jitter approach. The TRNG is a cryptographic-quality entropy source
//  compliant with NIST SP 800-90B, which is exactly what you want
//  as the foundation for ECDSA key generation.
//
//  In the Arduino-Pico framework for RP2350, the TRNG is exposed
//  through get_rand_32() from the Pico SDK's pico_rand library.
//  The framework also provides rp2350.hwrand32() as a wrapper,
//  but calling the SDK function directly is more explicit and
//  documents exactly what hardware you're relying on.
// ============================================================
static int rng_callback(uint8_t* dest, unsigned int size) {
    // get_rand_32() draws from the RP2350's hardware TRNG.
    // It returns a fresh 32-bit random word each call. We fill
    // the destination buffer 4 bytes at a time, handling the
    // case where size isn't a multiple of 4 with a partial copy.
    for (unsigned int i = 0; i < size; i += 4) {
        uint32_t r = get_rand_32();  // RP2350 hardware TRNG via Pico SDK
        unsigned int remaining = size - i;
        unsigned int chunk = remaining < 4 ? remaining : 4;
        memcpy(dest + i, &r, chunk);
    }
    return 1;  // micro-ecc convention: return 1 for success
}

// ============================================================
//  generateKeyPair
// ============================================================
bool generateKeyPair() {
    // Register the entropy source before any crypto operation.
    uECC_set_rng(rng_callback);

    const struct uECC_Curve_t* curve = uECC_secp256r1();

    int result = uECC_make_key(g_publicKey, g_privateKey, curve);
    if (result != 1) {
        Serial.println("[CRYPTO] ERROR: Key generation failed.");
        return false;
    }

    // Print the public key so it can be read from serial during demo setup.
    // The Auditor nodes need this to verify our anomaly broadcasts.
    char pubHex[PUBKEY_SIZE * 2 + 1];
    bytesToHex(g_publicKey, PUBKEY_SIZE, pubHex);
    Serial.print("[CRYPTO] Public key: ");
    Serial.println(pubHex);

    return true;
}

// ============================================================
//  sha256
// ============================================================
void sha256(const uint8_t* data, size_t dataLen, uint8_t outHash[HASH_SIZE]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, dataLen);
    sha256_final(&ctx, outHash);
}

// ============================================================
//  signPayload
// ============================================================
bool signPayload(const uint8_t* payload, size_t payloadLen,
                 uint8_t outSignature[SIG_SIZE]) {
    // Step 1: hash the payload.
    // ECDSA signs a hash, not the raw data. This is because the
    // P-256 field is 256 bits wide — you can't fit arbitrary data
    // into the signing equation directly.
    uint8_t hash[HASH_SIZE];
    sha256(payload, payloadLen, hash);

    // Step 2: sign the hash.
    const struct uECC_Curve_t* curve = uECC_secp256r1();
    int result = uECC_sign(g_privateKey, hash, HASH_SIZE, outSignature, curve);

    if (result != 1) {
        Serial.println("[CRYPTO] ERROR: Signing failed.");
        return false;
    }
    return true;
}

// ============================================================
//  verifySignature
//  This is the Sybil gate. Every UDP packet from an Auditor
//  passes through here before any other processing occurs.
// ============================================================
bool verifySignature(const uint8_t* payload, size_t payloadLen,
                     const uint8_t signature[SIG_SIZE],
                     const uint8_t senderPublicKey[PUBKEY_SIZE]) {
    uint8_t hash[HASH_SIZE];
    sha256(payload, payloadLen, hash);

    const struct uECC_Curve_t* curve = uECC_secp256r1();
    // uECC_verify returns 1 if the signature is valid, 0 if not.
    // It performs the full elliptic curve verification equation:
    //   (x, y) = (r^-1 * s * hash * G) + (r^-1 * r * publicKey)
    // If the x-coordinate of the resulting point mod n equals r,
    // the signature was produced by the matching private key.
    int result = uECC_verify(senderPublicKey, hash, HASH_SIZE, signature, curve);
    return (result == 1);
}

// ============================================================
//  bytesToHex
// ============================================================
void bytesToHex(const uint8_t* bytes, size_t len, char* outHex) {
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        outHex[i * 2]     = hexChars[(bytes[i] >> 4) & 0xF];
        outHex[i * 2 + 1] = hexChars[bytes[i] & 0xF];
    }
    outHex[len * 2] = '\0';
}

// ============================================================
//  hexToBytes
// ============================================================
bool hexToBytes(const char* hex, uint8_t* outBytes, size_t* outLen) {
    size_t hexLen = strlen(hex);
    if (hexLen % 2 != 0) return false;  // must be even number of chars

    *outLen = hexLen / 2;
    for (size_t i = 0; i < *outLen; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];

        auto hexVal = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int hiVal = hexVal(hi);
        int loVal = hexVal(lo);
        if (hiVal < 0 || loVal < 0) return false;  // invalid char
        outBytes[i] = (uint8_t)((hiVal << 4) | loVal);
    }
    return true;
}
