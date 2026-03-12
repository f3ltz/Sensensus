#pragma once

// ============================================================
//  crypto.h
//  Wraps micro-ecc (ECDSA) and mbedtls (SHA-256) into a clean
//  API the rest of the firmware can call without touching the
//  raw library internals.
//
//  WHY ECDSA over simpler HMAC?
//  HMAC requires both sides to share a secret key — fine for
//  two parties, but a shared secret in a swarm means any
//  compromised node can forge messages from all others.
//  ECDSA uses asymmetric keys: the Pico signs with its private
//  key; Auditors verify with the corresponding public key that
//  was broadcast during registration. No shared secret exists.
// ============================================================

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

// ---- Key storage (lives in RAM for prototype; flash-persist later) ----
extern uint8_t g_publicKey[PUBKEY_SIZE];
extern uint8_t g_privateKey[PRIVKEY_SIZE];

// ---- Lifecycle ----

/**
 * generateKeyPair()
 * Fills g_publicKey and g_privateKey with a fresh ECDSA P-256 key pair.
 * Call once during setup(). In production you would load from flash if
 * a key already exists so identity persists across reboots.
 * Returns true on success, false if the RNG entropy source failed.
 */
bool generateKeyPair();

// ---- Hashing ----

/**
 * sha256(data, dataLen, outHash)
 * Computes SHA-256 over `data` and writes the 32-byte digest into `outHash`.
 * You must hash a message before signing it — ECDSA operates on digests,
 * not raw messages, because P-256 arithmetic works in a 256-bit field.
 */
void sha256(const uint8_t* data, size_t dataLen, uint8_t outHash[HASH_SIZE]);

// ---- Signing ----

/**
 * signPayload(payload, payloadLen, outSignature)
 * Hashes payload with SHA-256 then signs the digest using g_privateKey.
 * outSignature must be a 64-byte buffer (32-byte r + 32-byte s).
 * Returns true on success.
 */
bool signPayload(const uint8_t* payload, size_t payloadLen,
                 uint8_t outSignature[SIG_SIZE]);

// ---- Verification ----

/**
 * verifySignature(payload, payloadLen, signature, senderPublicKey)
 * Hashes payload, then checks that `signature` was produced by the
 * private key matching `senderPublicKey`. This is the Sybil gate —
 * any packet that fails this check is dropped before touching state.
 * Returns true only if the signature is cryptographically valid.
 */
bool verifySignature(const uint8_t* payload, size_t payloadLen,
                     const uint8_t signature[SIG_SIZE],
                     const uint8_t senderPublicKey[PUBKEY_SIZE]);

// ---- Utility ----

/**
 * bytesToHex(bytes, len, outHex)
 * Converts a byte array to a null-terminated hex string.
 * outHex must be at least (len * 2 + 1) bytes.
 * Used when embedding keys/signatures in JSON payloads.
 */
void bytesToHex(const uint8_t* bytes, size_t len, char* outHex);

/**
 * hexToBytes(hex, outBytes, outLen)
 * Inverse of bytesToHex. Returns false if the string isn't valid hex.
 */
bool hexToBytes(const char* hex, uint8_t* outBytes, size_t* outLen);
