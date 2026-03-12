#pragma once

// ============================================================
//  network.h
//  UDP multicast Sybil gate + x402 HTTP server + Flow submission
//
//  KEY ARCHITECTURAL POINTS:
//  - Auditors must beacon before they can bid (registry gate)
//  - Bids collected for BID_COLLECTION_MS then quorum selected
//  - Pico sends directed PKT_QUORUM to each winner — auditors
//    do NOT poll; they wait for notification
//  - Only quorum auditors can access GET /data (403 otherwise)
//  - POST /pay response contains { csv + signed payload }
//  - Pico posts its own anomaly claim to Flow after delivering
//  - Pico never reports on auditor verdicts — that's their job
// ============================================================

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "crypto.h"

// ---------- Packet type bytes ----------
#define PKT_BEACON   0x01
#define PKT_BID      0x02
#define PKT_ANOMALY  0x03
#define PKT_QUORUM   0x04

// ---------- Packet sizes ----------
#define PKT_HEADER_SIZE  (1 + PUBKEY_SIZE)              // 65 bytes
#define PKT_SIGNED_SIZE  (PKT_HEADER_SIZE + SIG_SIZE)   // 129 bytes
#define PKT_ANOMALY_SIZE (PKT_HEADER_SIZE + 4 + SIG_SIZE) // 133 bytes

// ---------- Auditor registry ----------
struct AuditorRecord {
    uint8_t  publicKey[PUBKEY_SIZE];
    char     ipAddress[16];
    uint16_t port;
    uint32_t lastSeenMs;
    bool     active;
    bool     inQuorum;      // true after quorum selection for current event
    bool     served;        // true after successful POST /pay for current event
};

extern AuditorRecord g_auditorRegistry[MAX_AUDITORS];
extern int           g_auditorCount;

// Bid pool — filled during BID_COLLECTION_MS window
struct BidRecord {
    uint8_t  publicKey[PUBKEY_SIZE];
    char     ipAddress[16];
    uint16_t port;
};
extern BidRecord g_bidPool[MAX_AUDITORS];
extern int       g_bidCount;

// Quorum tracking
extern int  g_quorumSize;
extern int  g_servedCount;   // increments each time a quorum auditor completes /pay

// ---- Lifecycle ----
bool net_init();

// ---- Per-loop handlers ----
void net_handleUdp();
void net_handleHttp();

// ---- Outbound ----
void net_broadcastAnomaly(float confidence);

/**
 * net_selectQuorumAndNotify(confidence)
 * Called after BID_COLLECTION_MS expires.
 * Queries Flow for stake balances of all bidders (stubbed for now),
 * marks top MAX_QUORUM_SIZE bidders as inQuorum in registry,
 * sends directed PKT_QUORUM UDP to each winner.
 */
void net_selectQuorumAndNotify();

/**
 * net_resetEvent()
 * Clears quorum flags, bid pool, and served counters.
 * Called when returning to IDLE.
 */
void net_resetEvent();

/**
 * net_allQuorumServed()
 * Returns true when every quorum auditor has completed POST /pay.
 */
bool net_allQuorumServed();

const char* net_getLocalIp();
