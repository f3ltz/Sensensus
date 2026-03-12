#pragma once
#include <stdint.h>

// Crypto geometry
#define PUBKEY_BYTES   64
#define PRIVKEY_BYTES  32
#define SIG_BYTES      64
#define HASH_BYTES     32
#define PUBKEY_HEX_LEN 128   // 64 bytes → 128 hex chars

// Registry limits
#define MAX_AUDITORS   16
#define MAX_QUORUM     QUORUM_SIZE
#define NONCE_BYTES    16

// State machine
typedef enum {
    STATE_IDLE,
    STATE_ANOMALY,
    STATE_DELIVERING,
} SystemState;