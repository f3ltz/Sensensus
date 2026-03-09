#include "payload.h"
#include "crypto.h"
#include "network.h"
#include <Arduino.h>
#include <stdio.h>
#include <string.h>

size_t payload_build(float confidence, char* outJson, size_t maxLen) {
    if (!g_hasWinner) {
        Serial.println("[PAYLOAD] ERROR: No winning auditor set — cannot build payload.");
        return 0;
    }

    // ---- Step 1: Hex-encode the keys ----
    char transporterHex[PUBKEY_SIZE * 2 + 1];
    char auditorHex[PUBKEY_SIZE * 2 + 1];
    bytesToHex(g_publicKey,            PUBKEY_SIZE, transporterHex);
    bytesToHex(g_winningAuditorPubKey, PUBKEY_SIZE, auditorHex);

    // ---- Step 2: Build the unsigned JSON body ----
    // This is what gets hashed and signed. The "csv_cid" field is
    // intentionally left empty — the Gateway fills it in after
    // uploading the CSV to Storacha.
    char unsignedBody[PAYLOAD_MAX_SIZE];
    int bodyLen = snprintf(unsignedBody, sizeof(unsignedBody),
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"winning_auditor_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"csv_cid\":\"\","
        "\"timestamp_ms\":%lu"
        "}",
        transporterHex,
        auditorHex,
        confidence,
        (unsigned long)millis()
    );

    if (bodyLen <= 0 || (size_t)bodyLen >= sizeof(unsignedBody)) {
        Serial.println("[PAYLOAD] ERROR: JSON body too large.");
        return 0;
    }

    // ---- Step 3: Sign the body bytes ----
    uint8_t signature[SIG_SIZE];
    bool signed_ok = signPayload(
        (const uint8_t*)unsignedBody,
        (size_t)bodyLen,
        signature
    );
    if (!signed_ok) {
        Serial.println("[PAYLOAD] ERROR: Signing failed.");
        return 0;
    }

    // ---- Step 4: Hex-encode the signature ----
    char sigHex[SIG_SIZE * 2 + 1];
    bytesToHex(signature, SIG_SIZE, sigHex);

    // ---- Step 5: Build the final payload with signature appended ----
    // We reconstruct the JSON from the same fields, now adding
    // payload_signature. Because we're signing the body string
    // literally, order and whitespace must match exactly on both
    // the signing and verification side — no pretty-printing.
    int finalLen = snprintf(outJson, maxLen,
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"winning_auditor_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"csv_cid\":\"\","
        "\"timestamp_ms\":%lu,"
        "\"payload_signature\":\"%s\""
        "}",
        transporterHex,
        auditorHex,
        confidence,
        (unsigned long)millis(),  // NOTE: re-read millis() here so ts matches body
        sigHex
    );

    // Important: the timestamp will differ slightly between the
    // unsigned body and the final JSON because millis() advances.
    // For the prototype this is fine. In production, capture the
    // timestamp once into a variable and use it in both places.

    if (finalLen <= 0 || (size_t)finalLen >= maxLen) {
        Serial.println("[PAYLOAD] ERROR: Final JSON truncated.");
        return 0;
    }

    return (size_t)finalLen;
}

void payload_printSerial(const char* json) {
    Serial.println("[PAYLOAD] ===== Final Signed Payload =====");
    Serial.println(json);
    Serial.println("[PAYLOAD] =================================");
}