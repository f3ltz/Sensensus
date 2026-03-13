#pragma once
// gateway.h — Pico 2W application-layer gateway
// Wraps flow_tx.h and the Storacha HTTPS upload behind simple call sites.
// All FLOW_ENABLED=0 paths are simulated locally; no relay server is used.
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// ── Boot ──────────────────────────────────────────────────────────────────────
// Call from setup() after WiFi connects. Initialises flow_tx module and
// optionally calls registerNode (idempotent — safe on every cold boot).
void gateway_init(const uint8_t *priv_32);

// ── Storacha ──────────────────────────────────────────────────────────────────
bool gateway_storacha_upload(const char *csv_data, char *cid_out, size_t cid_out_size);

// ── Flow Phase 1 ─────────────────────────────────────────────────────────────
// Locks bid escrow. Waits for seal — PKT_QUORUM must not fire before this returns.
bool gateway_register_anomaly(
    const char  *transporter_pub_hex,
    const char  *submission_sig_hex,
    float        anomaly_confidence,
    const char **quorum_ids,
    int          quorum_count,
    float        payment_per_auditor
);

// ── Flow Phase 1.5 ───────────────────────────────────────────────────────────
// Lock auditor deposit on-chain. Waits for seal.
// Returns false → caller must return HTTP 503, do NOT send CSV.
bool gateway_submit_deposit(
    const char *event_id,
    const char *auditor_pub_hex,
    float       deposit_amount,
    float       bid_amount
);

// ── Flow Phase 3 ─────────────────────────────────────────────────────────────
// Trigger finalisation (fire-and-forget).
bool gateway_finalize_event(const char *event_id);

// ── Flow post-consensus ───────────────────────────────────────────────────────
// Record Storacha CID (fire-and-forget).
bool gateway_update_event_cid(const char *event_id, const char *cid);

// ── Flow read-only ────────────────────────────────────────────────────────────
// Fetch stake + reputation for quorum scoring.
bool gateway_query_node(const char *pub_hex, float *stake_out, float *rep_out);