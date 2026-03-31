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

// Quorum
#ifndef QUORUM_SIZE
#define QUORUM_SIZE        3
#endif
#ifndef QUORUM_W_PRICE
#define QUORUM_W_PRICE     0.5f
#endif
#ifndef QUORUM_W_REP
#define QUORUM_W_REP       0.3f
#endif
#ifndef QUORUM_W_STAKE
#define QUORUM_W_STAKE     0.2f
#endif

// Timing (ms)
#ifndef BID_WINDOW_MS
#define BID_WINDOW_MS      600
#endif
#ifndef DELIVERY_TIMEOUT_MS
#define DELIVERY_TIMEOUT_MS 60000
#endif

// IMU / inference
#ifndef SAMPLE_RATE_HZ
#define SAMPLE_RATE_HZ     50
#endif
#ifndef WINDOW_SIZE_SAMPLES
#define WINDOW_SIZE_SAMPLES 50
#endif
#ifndef INPUT_TENSOR_SIZE
#define INPUT_TENSOR_SIZE  350
#endif
#ifndef CSV_BUFFER_SAMPLES
#define CSV_BUFFER_SAMPLES 75
#endif
#ifndef TENSOR_ARENA_SIZE
#define TENSOR_ARENA_SIZE  (96 * 1024)
#endif
#ifndef ANOMALY_CONFIDENCE_THRESHOLD
#define ANOMALY_CONFIDENCE_THRESHOLD 0.85f
#endif
#ifndef HTTP_PORT
#define HTTP_PORT          8080
#endif
#ifndef MULTICAST_PORT
#define MULTICAST_PORT     5005
#endif
#ifndef BID_PORT
#define BID_PORT           5006
#endif
#ifndef DEPOSIT_AMOUNT
#define DEPOSIT_AMOUNT     0.5f
#endif