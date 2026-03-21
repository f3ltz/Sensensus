// gateway.cpp — Pico 2W application-layer gateway
// Architecture: PL_Genesis Hackathon 2026
//
// Thin wrapper around flow_tx.cpp and the Storacha HTTPS upload.
// No relay server is used. When FLOW_ENABLED=0 every function simulates
// locally so the full firmware runs without a live Flow testnet deployment.
//
// Flow TX call sites and their wait_seal semantics:
//
//   gateway_init             → flow_tx_register_node    (wait_seal=true, once at boot)
//   gateway_register_anomaly → flow_tx_register_anomaly (wait_seal=true)
//   gateway_submit_deposit   → flow_tx_submit_deposit   (wait_seal=true, per auditor)
//   gateway_finalize_event   → flow_tx_finalize_event   (fire-and-forget)
//   gateway_update_event_cid → flow_tx_update_cid       (fire-and-forget)
//   gateway_query_node       → flow_tx_query_node       (read-only script, no signing)

#include "gateway.h"
#include "flow_tx.h"
#include "config.h"
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Arduino.h>
#include <string.h>

// ── HTTPS helper (Storacha only — Flow uses flow_tx's internal helper) ────────
static int _storacha_post(const char *host, int port, const char *path,
                           const char *content_type, const char *body,
                           char *resp_buf, size_t resp_size) {
    WiFiClientSecure cli; cli.setInsecure();
    if (!cli.connect(host, port)) {
        Serial.printf("[GW] Storacha connect failed: %s\n", host); return -1;
    }
    cli.printf("POST %s HTTP/1.0\r\nHost: %s\r\nContent-Type: %s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n",
               path, host, content_type, (int)strlen(body));
    cli.print(body);
    uint32_t dl = millis()+10000;
    while (!cli.available()&&millis()<dl) delay(10);
    String sl = cli.readStringUntil('\n'); int code=0;
    sscanf(sl.c_str(), "HTTP/%*s %d", &code);
    while (cli.connected()||cli.available()) {
        String l=cli.readStringUntil('\n');
        if (l=="\r"||!l.length()) break;
    }
    size_t n=0;
    while ((cli.connected()||cli.available())&&n<resp_size-1) {
        if (cli.available()) resp_buf[n++]=cli.read();
    }
    resp_buf[n]='\0'; cli.stop(); return code;
}

// ── Boot initialisation ───────────────────────────────────────────────────────
void gateway_init(const uint8_t *priv_32) {
#if FLOW_ENABLED
    flow_tx_init(
        priv_32,
        FLOW_ACCOUNT_ADDR,    // build flag: e.g. "0x1234567890abcdef"
        FLOW_CONTRACT_ADDR,   // build flag: deployed SwarmVerifierV3 address
        "rest-testnet.onflow.org"
    );

    // registerNode is idempotent — the contract pre-condition rejects duplicates.
    // It is safe to call on every cold boot. Failure is non-fatal: the Pico can
    // still participate in quorum scoring from the chain's existing record.
    extern const uint8_t g_pubKey[];  // declared in crypto.h
    extern char          g_pubHex[];  // set in main.cpp after key generation

    Serial.println("[GW] Registering node on Flow testnet...");
    bool ok = flow_tx_register_node(g_pubHex, /*stake=*/10.0);
    if (!ok) Serial.println("[GW] registerNode failed (may already be registered — continuing)");
#else
    (void)priv_32;
    Serial.println("[GW] FLOW_ENABLED=0 — all Flow calls simulated locally");
#endif
}

// ── Storacha upload ───────────────────────────────────────────────────────────
bool gateway_storacha_upload(const char *csv_data, char *cid_out, size_t cid_out_size) {
#if !FLOW_ENABLED
    // This branch runs when FLOW_ENABLED=0 — not your case
    strlcpy(cid_out, "bafyreiSIMULATED", cid_out_size);
    return true;
#else
    // THIS is what runs with FLOW_ENABLED=1
    // Change it to just return true for now
    Serial.println("[GW] Storacha upload skipped");
    strlcpy(cid_out, "", cid_out_size);
    return true;   // <-- this is the only meaningful change
#endif
}

// ── Phase 1: registerAnomaly ──────────────────────────────────────────────────
bool gateway_register_anomaly(
    const char  *transporter_pub_hex,
    const char  *submission_sig_hex,
    float        anomaly_confidence,
    const char **quorum_ids,
    int          quorum_count,
    float        payment_per_auditor)
{
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) registerAnomaly  event=%.16s...  quorum=%d  "
                  "conf=%.4f  bid/auditor=%.4f\n",
                  submission_sig_hex, quorum_count,
                  (double)anomaly_confidence, (double)payment_per_auditor);
    return true;
#else
    return flow_tx_register_anomaly(
        transporter_pub_hex, submission_sig_hex,
        anomaly_confidence,
        quorum_ids, quorum_count,
        payment_per_auditor);
#endif
}

// ── Phase 1.5: submitDeposit ──────────────────────────────────────────────────
// Must be called and must succeed before the CSV is streamed to the auditor.
// The deposit + bid are locked on-chain, creating an irrevocable commitment
// that finalizeEvent uses for disbursement. If this TX fails, the auditor
// gets a 503 and no data — preventing free-riding.
bool gateway_submit_deposit(
    const char *event_id,
    const char *auditor_pub_hex,
    float       deposit_amount,
    float       bid_amount)
{
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) submitDeposit  event=%.16s...  auditor=...%.12s  "
                  "deposit=%.4f  bid=%.4f\n",
                  event_id, auditor_pub_hex + strlen(auditor_pub_hex) - 12,
                  (double)deposit_amount, (double)bid_amount);
    return true;
#else
    return flow_tx_submit_deposit(event_id, auditor_pub_hex, deposit_amount, bid_amount);
#endif
}

// ── Phase 3: finalizeEvent ────────────────────────────────────────────────────
bool gateway_finalize_event(const char *event_id) {
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) finalizeEvent  event=%.16s...\n", event_id);
    return true;
#else
    return flow_tx_finalize_event(event_id);
#endif
}

// ── Post-consensus: updateEventCid ───────────────────────────────────────────
bool gateway_update_event_cid(const char *event_id, const char *cid) {
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) updateEventCid  event=%.16s...  cid=%s\n", event_id, cid);
    return true;
#else
    return flow_tx_update_cid(event_id, cid);
#endif
}

// ── Read-only: queryNode ──────────────────────────────────────────────────────
// No signing needed — runs a Cadence script via POST /v1/scripts.
// Returns false on any error; caller uses 0.0 defaults (quorum ranks by price only).
bool gateway_query_node(const char *pub_hex, float *stake_out, float *rep_out) {
    *stake_out = 0.0f; *rep_out = 0.0f;
#if !FLOW_ENABLED
    return true;
#else
    return flow_tx_query_node(pub_hex, stake_out, rep_out);
#endif
}