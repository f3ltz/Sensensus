#include "gateway.h"
#include "config.h"
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Arduino.h>
#include <string.h>

// ── Internal HTTPS helper ─────────────────────────────────────────────────────
// For testnet/demo we use setInsecure() — acceptable for a hackathon.
// For production: load the ISRG Root X1 certificate via setCACert().
static int _https_post(const char *host, int port, const char *path,
                       const char *content_type, const char *body,
                       char *resp_buf, size_t resp_buf_size) {
    WiFiClientSecure cli;
    cli.setInsecure();   // skip cert validation — fine for testnet demo
    if (!cli.connect(host, port)) {
        Serial.printf("[GW] HTTPS connect to %s failed\n", host);
        return -1;
    }
    cli.printf("POST %s HTTP/1.0\r\n", path);
    cli.printf("Host: %s\r\n", host);
    cli.printf("Content-Type: %s\r\n", content_type);
    cli.printf("Content-Length: %d\r\n", (int)strlen(body));
    cli.printf("Connection: close\r\n\r\n");
    cli.print(body);

    uint32_t deadline = millis() + 10000;
    while (!cli.available() && millis() < deadline) delay(10);

    // Read status line
    String status_line = cli.readStringUntil('\n');
    int code = 0;
    sscanf(status_line.c_str(), "HTTP/%*s %d", &code);

    // Skip headers
    while (cli.connected() || cli.available()) {
        String line = cli.readStringUntil('\n');
        if (line == "\r" || line.length() == 0) break;
    }

    // Read body
    size_t n = 0;
    while ((cli.connected() || cli.available()) && n < resp_buf_size - 1) {
        if (cli.available()) resp_buf[n++] = cli.read();
    }
    resp_buf[n] = '\0';
    cli.stop();
    return code;
}

// ── Storacha upload ───────────────────────────────────────────────────────────
bool gateway_storacha_upload(const char *csv_data, char *cid_out, size_t cid_out_size) {
#if !FLOW_ENABLED
    // Simulation: generate a plausible-looking fake CID
    strlcpy(cid_out, "bafyreiSIMULATED000000000000000000", cid_out_size);
    Serial.println("[GW] Storacha (simulated) — fake CID generated");
    return true;
#else
    // Real path: POST multipart/form-data to STORACHA_UPLOAD_URL
    // w3up expects a CAR file, but for demo we post raw bytes with a filename hint.
    // Production implementation should construct a proper UnixFS CAR file.
    char resp[512] = {};
    // Build minimal JSON body (w3up REST API)
    char body[16384];
    snprintf(body, sizeof(body),
        "--boundary\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"imu.csv\"\r\n"
        "Content-Type: text/csv\r\n\r\n%s\r\n"
        "--boundary--\r\n",
        csv_data);

    int code = _https_post("up.web3.storage", 443, "/upload",
                           "multipart/form-data; boundary=boundary",
                           body, resp, sizeof(resp));
    if (code != 200 && code != 201) {
        Serial.printf("[GW] Storacha upload failed: HTTP %d\n", code);
        return false;
    }
    StaticJsonDocument<256> doc;
    if (deserializeJson(doc, resp) == DeserializationError::Ok) {
        const char *cid = doc["cid"] | "";
        strlcpy(cid_out, cid, cid_out_size);
        Serial.printf("[GW] Storacha CID=%s\n", cid_out);
        return strlen(cid_out) > 0;
    }
    return false;
#endif
}

// ── Flow: registerAnomaly ─────────────────────────────────────────────────────
bool gateway_register_anomaly(
    const char *transporter_pub_hex,
    const char *submission_sig_hex,
    float        anomaly_confidence,
    const char **quorum_ids,
    int          quorum_count,
    float        payment_per_auditor)
{
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) registerAnomaly  event=%.16s...  quorum=%d  conf=%.4f\n",
                  submission_sig_hex, quorum_count, anomaly_confidence);
    return true;
#else
    // Build Cadence transaction JSON.
    // Flow REST API: POST /v1/transactions
    // For the hackathon the deployer account holds the Gateway resource.
    // The Pico signs the transaction envelope with its P-256 private key
    // (Flow natively supports secp256r1 account keys).
    //
    // Full transaction construction is omitted here — it requires:
    //   1. GET /v1/accounts/<addr> to fetch sequence number
    //   2. Encode Cadence transaction envelope (RLP-like encoding)
    //   3. Sign with Pico private key
    //   4. POST /v1/transactions
    //
    // TODO: implement when deploying to testnet
    Serial.println("[GW] Flow registerAnomaly — live submission not yet implemented");
    return false;
#endif
}

// ── Flow: updateEventCid ──────────────────────────────────────────────────────
bool gateway_update_event_cid(const char *event_id, const char *cid) {
#if !FLOW_ENABLED
    Serial.printf("[GW] (sim) updateEventCid  event=%.16s...  cid=%s\n", event_id, cid);
    return true;
#else
    // TODO: same transaction construction as registerAnomaly
    Serial.println("[GW] Flow updateEventCid — live submission not yet implemented");
    return false;
#endif
}

// ── Flow: getStake / getReputation ────────────────────────────────────────────
bool gateway_query_node(const char *pub_hex, float *stake_out, float *rep_out) {
    *stake_out = 0.0f;
    *rep_out   = 0.0f;

#if !FLOW_ENABLED
    return true;   // caller will use 0.0 defaults — quorum ranks by price only
#else
    // POST to Flow REST script endpoint
    // Script returns [Fix64?, Fix64] for [stake, reputation]
    char script_b64[512]; // TODO: base64-encode the Cadence script
    char arg_b64[512];    // TODO: base64-encode {"type":"String","value":"<pub_hex>"}
    char body[1024];
    snprintf(body, sizeof(body),
        "{\"script\":\"%s\",\"arguments\":[\"%s\"]}",
        script_b64, arg_b64);

    char resp[512] = {};
    int code = _https_post("rest-testnet.onflow.org", 443, "/v1/scripts",
                           "application/json", body, resp, sizeof(resp));
    if (code != 200) return false;

    // Parse response — TODO: base64-decode value, parse Cadence JSON
    // For now fall through to defaults
    return false;
#endif
}