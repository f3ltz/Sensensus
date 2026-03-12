// ============================================================
//  payload.cpp
//  Builds a signed JSON payload for a specific auditor.
//  Called once per quorum auditor during POST /pay handling.
//
//  What gets signed:
//    { transporter_pubkey, auditor_pubkey, anomaly_confidence,
//      timestamp_ms }
//  The signature proves this specific interaction happened between
//  this Pico and this auditor at this confidence and time.
//  The auditor includes payload_signature in their verdict
//  submission to Flow to tie their verdict back to this event.
//
//  What is NOT here:
//    csv_cid — the top-ranked auditor uploads CSV to Storacha
//    and includes the CID in their own verdict submission.
//    The Pico never touches Storacha.
// ============================================================

#include "payload.h"
#include "crypto.h"
#include "network.h"
#include <Arduino.h>
#include <stdio.h>
#include <string.h>

// Module-level confidence — set by main.cpp when infer_run() fires.
float g_lastConfidence = 0.0f;

// ============================================================
//  payload_build
// ============================================================
size_t payload_build(const uint8_t auditorPubKey[PUBKEY_SIZE],
                     char* outJson, size_t maxLen) {
    // ---- Hex-encode keys ----
    char transporterHex[PUBKEY_SIZE * 2 + 1];
    char auditorHex[PUBKEY_SIZE * 2 + 1];
    bytesToHex(g_publicKey,  PUBKEY_SIZE, transporterHex);
    bytesToHex(auditorPubKey, PUBKEY_SIZE, auditorHex);

    // ---- Capture timestamp ONCE ----
    // Using millis() twice (once for body, once for final JSON) causes a
    // mismatch because millis() advances. Capture it here, use it everywhere.
    uint32_t ts = (uint32_t)millis();

    // ---- Build unsigned body (this is what gets signed) ----
    char unsignedBody[PAYLOAD_MAX_SIZE];
    int bodyLen = snprintf(unsignedBody, sizeof(unsignedBody),
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"auditor_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"timestamp_ms\":%lu"
        "}",
        transporterHex,
        auditorHex,
        g_lastConfidence,
        (unsigned long)ts
    );

    if (bodyLen <= 0 || (size_t)bodyLen >= sizeof(unsignedBody)) {
        Serial.println("[PAYLOAD] ERROR: Body too large.");
        return 0;
    }

    // ---- Sign ----
    uint8_t signature[SIG_SIZE];
    if (!signPayload((const uint8_t*)unsignedBody, (size_t)bodyLen, signature)) {
        Serial.println("[PAYLOAD] ERROR: Signing failed.");
        return 0;
    }

    // ---- Encode sig ----
    char sigHex[SIG_SIZE * 2 + 1];
    bytesToHex(signature, SIG_SIZE, sigHex);

    // ---- Build final JSON (body + signature, same ts) ----
    int finalLen = snprintf(outJson, maxLen,
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"auditor_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"timestamp_ms\":%lu,"
        "\"payload_signature\":\"%s\""
        "}",
        transporterHex,
        auditorHex,
        g_lastConfidence,
        (unsigned long)ts,
        sigHex
    );

    if (finalLen <= 0 || (size_t)finalLen >= maxLen) {
        Serial.println("[PAYLOAD] ERROR: Final JSON truncated.");
        return 0;
    }

    return (size_t)finalLen;
}
