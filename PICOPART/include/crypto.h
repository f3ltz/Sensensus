#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

extern uint8_t g_publicKey[PUBKEY_SIZE];
extern uint8_t g_privateKey[PUBKEY_SIZE];

bool generateKeyPair();

void sha256(const uint8_t* data, size_t dataLen, uint8_t outHash[HASH_SIZE]);

bool signPayload(const uint8_t* payload, size_t payloadLen, uint8_t outSignature[SIG_SIZE]);

bool verifySignature(const uint8_t* payload, size_t payloadLen,
                     const uint8_t signature[SIG_SIZE],
                     const uint8_t senderPublicKey[PUBKEY_SIZE]);

void bytesToHex(const uint8_t* bytes, size_t len, char* outHex);
bool hexToBytes(const char* hex, uint8_t* outBytes, size_t* outLen);