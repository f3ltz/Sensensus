#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "config.h"

// ── Auditor registry entry ───────────────────────────────────────────────────
struct AuditorEntry {
    uint8_t  pubkey[PUBKEY_BYTES];
    char     pubkey_hex[PUBKEY_HEX_LEN + 1];
    char     ip[20];
    uint32_t last_seen_ms;
    bool     active;
};

// ── Bid entry ────────────────────────────────────────────────────────────────
struct BidEntry {
    char     pubkey_hex[PUBKEY_HEX_LEN + 1];
    char     ip[20];
    double   price;
    float    rep;    // queried from Flow (0.0 if FLOW_ENABLED=0)
    float    stake;  // queried from Flow (0.0 if FLOW_ENABLED=0)
    float    score;
};

// ── Nonce entry (keyed by pubkey_hex) ────────────────────────────────────────
struct NonceEntry {
    char    pubkey_hex[PUBKEY_HEX_LEN + 1];
    uint8_t nonce[NONCE_BYTES];
    bool    valid;
};

// ── Quorum member ─────────────────────────────────────────────────────────────
struct QuorumEntry {
    char    pubkey_hex[PUBKEY_HEX_LEN + 1];
    uint8_t pubkey[PUBKEY_BYTES];
    char    ip[20];
};

// ── Globals accessible from main / network ───────────────────────────────────
extern AuditorEntry  g_auditorRegistry[MAX_AUDITORS];
extern int           g_auditorCount;
extern BidEntry      g_bidPool[MAX_AUDITORS];
extern int           g_bidCount;
extern QuorumEntry   g_quorum[MAX_QUORUM];
extern int           g_quorumSize;
extern NonceEntry    g_nonces[MAX_QUORUM];
extern bool          g_collectingBids;
extern char          g_csvBuffer[8192];    // current event CSV

// ── Init / tick ───────────────────────────────────────────────────────────────
bool net_init();
void net_handleUdp();    // call from main loop — polls both UDP sockets
void net_handleHttp();   // call from main loop — processes one client if waiting

// ── Packet builders / senders ────────────────────────────────────────────────
void net_sendAnomaly(float confidence);
void net_sendQuorumNotify(const QuorumEntry *entry);

// ── Quorum selection (call after bid window closes) ───────────────────────────
int  net_selectQuorum(const char *transporter_pub_hex);