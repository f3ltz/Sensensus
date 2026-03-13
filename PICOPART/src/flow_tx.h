#pragma once
// flow_tx.h — on-device Flow transaction construction for the Pico 2W (RP2350)
// Architecture: PL_Genesis Hackathon 2026
//
// All blockchain I/O goes through this module. No relay server is involved.
//
// TX signing pipeline:
//   1. GET /v1/blocks?height=sealed        → 32-byte reference block ID
//   2. GET /v1/accounts/{addr}?expand=keys → key[0].sequence_number
//   3. RLP-encode the signing payload
//   4. envelope = DOMAIN_TAG(32B) || RLP([payload_rlp, []])
//   5. hash     = SHA3-256(envelope)        (SW — RP2350 HW only has SHA-256)
//   6. sig      = uECC_sign(priv, hash)     (same call as crypto.cpp)
//   7. POST /v1/transactions                (base64-encoded fields)
//   8. Poll until SEALED when wait_seal=true

#include <stdint.h>
#include <stdbool.h>

// Call once from setup().
void flow_tx_init(
    const uint8_t *priv_32,        // 32-byte P-256 private key
    const char    *account_addr,   // "0x<16 hex>" — this Pico's Flow account
    const char    *contract_addr,  // "0x<16 hex>" — deployed SwarmVerifierV3
    const char    *api_host        // "rest-testnet.onflow.org" (no scheme)
);

// Registration — idempotent, called at boot. Waits for seal.
bool flow_tx_register_node(const char *node_id, double stake_flow);

// Phase 1 — register anomaly event. Waits for seal before PKT_QUORUM fires.
bool flow_tx_register_anomaly(
    const char  *transporter_pub_hex,
    const char  *submission_sig_hex,
    float        anomaly_confidence,
    const char **quorum_ids,
    int          n_quorum,
    float        payment_per_auditor
);

// Phase 1.5 — record auditor deposit + bid. Waits for seal before CSV sent.
// Returns false on TX failure → caller returns 503 to auditor, no CSV.
bool flow_tx_submit_deposit(
    const char *event_id,
    const char *auditor_pub_hex,
    float       deposit_amount,
    float       bid_amount
);

// Phase 3 — trigger finalisation (fire-and-forget).
bool flow_tx_finalize_event(const char *event_id);

// Post-consensus — record Storacha CID (fire-and-forget).
bool flow_tx_update_cid(const char *event_id, const char *cid);

// Read-only script — query node stake + reputation. No signing required.
bool flow_tx_query_node(const char *pub_hex, float *stake_out, float *rep_out);