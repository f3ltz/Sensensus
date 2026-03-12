#pragma once
#include <stddef.h>
#include <stdbool.h>

// Upload CSV to Storacha via w3up HTTP API.
// On success: sets cid_out (max 128 chars) and returns true.
// On failure: returns false (caller should abort the event).
bool gateway_storacha_upload(const char *csv_data, char *cid_out, size_t cid_out_size);

// Phase 1: register anomaly on Flow contract.
// Returns true if accepted (or FLOW_ENABLED=0, in which case it's a no-op).
bool gateway_register_anomaly(
    const char *transporter_pub_hex,
    const char *submission_sig_hex,
    float        anomaly_confidence,
    const char **quorum_ids,          // array of pubkey_hex strings
    int          quorum_count,
    float        payment_per_auditor
);

// Post-consensus: record Storacha CID on Flow contract.
bool gateway_update_event_cid(const char *event_id, const char *cid);

// Query stake and reputation for a node from the Flow contract.
// Sets stake_out / rep_out. Returns false on network error (caller uses 0.0 defaults).
bool gateway_query_node(const char *pub_hex, float *stake_out, float *rep_out);