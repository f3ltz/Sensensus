#include "crypto.h"

#include <Arduino.h>
#include <string.h>

#include "uECC.h"
#include "sha256.h"
#include "pico/rand.h"

uint8_t g_publicKey[PUBKEY_SIZE];
uint8_t g_privateKey[PRIVKEY_SIZE];

static int rng_callback(uint8_t* dest, unsigned int size) {
    for (unsigned int i = 0; i < size; i += 4) {
        uint32_t r = get_rand_32();
        unsigned int remaining = size - i;
        unsigned int chunk = remaining < 4 ? remaining : 4;
        memcpy(dest + i, &r, chunk);
    }
    return 1;
}

bool generateKeyPair() {
    uECC_set_rng(rng_callback);

    const struct uECC_Curve_t* curve = uECC_secp256r1();

    int result = uECC_make_key(g_publicKey, g_privateKey, curve);
    if (result != 1) {
        Serial.println("[Crypto] ERROR: Key generation failed.");
        return false;
    }

    char pubHex[PUBKEY_SIZE * 2 + 1];
    bytesToHex(g_publicKey, PUBKEY_SIZE, pubHex);
    Serial.print("[CRYPTO] Public key: ");
    Serial.println(pubHex);

    return true;
}

void sha256 (const uint8_t* data, size_t dataLen, uint8_t outHash[HASH_SIZE]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, dataLen);
    sha256_final(&ctx, outHash);
}

bool signPayload(const uint8_t* payload, size_t payloadLen, uint8_t outSignature[SIG_SIZE]){
    uint8_t hash[HASH_SIZE];
    sha256(payload, payloadLen, hash);

    const struct uECC_Curve_t* curve = uECC_secp256r1();
    int result = uECC_sign(g_privateKey, hash, HASH_SIZE, outSignature, curve);

    if (result != 1) {
        Serial.println("[CRYPTO] ERROR: Signing Failed.");
        return 0;
    }

    return 1;
}

bool verifySignature(const uint8_t* payload, size_t payloadLen, const uint8_t signature[SIG_SIZE], const uint8_t senderPublicKey[PUBKEY_SIZE]){
    uint8_t hash[HASH_SIZE];
    sha256(payload, payloadLen, hash);
    const struct uECC_Curve_t* curve = uECC_secp256r1();

    int result = uECC_verify(senderPublicKey, hash, HASH_SIZE, signature, curve);
    return (result == 1);
}

void bytesToHex(const uint8_t* bytes, size_t len, char* outHex) {
    static const char hexChars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        outHex[i * 2]     = hexChars[(bytes[i] >> 4) & 0xF];
        outHex[i * 2 + 1] = hexChars[bytes[i] & 0xF];
    }
    outHex[len * 2] = '\0';
}

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