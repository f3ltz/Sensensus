// ============================================================
//  gateway.cpp
//  Posts the Pico's signed anomaly claim to the Flow relay.
// ============================================================

#include "gateway.h"
#include "crypto.h"
#include "config.h"
#include <Arduino.h>
#include <WiFiClient.h>
#include <stdio.h>
#include <string.h>

// ============================================================
//  gateway_postAnomalyClaim
// ============================================================
bool gateway_postAnomalyClaim(float confidence,
                               const uint8_t quorumPubKeys[][64],
                               int quorumSize) {
    // ---- Build the unsigned JSON body ----
    // Contains everything the Flow contract needs to verify:
    //   - Which Pico sent this (transporter_pubkey)
    //   - What it detected (anomaly_confidence)
    //   - When (timestamp_ms)
    //   - Which auditors were selected (quorum_auditor_pubkeys[])

    char transporterHex[PUBKEY_SIZE * 2 + 1];
    bytesToHex(g_publicKey, PUBKEY_SIZE, transporterHex);

    uint32_t ts = (uint32_t)millis();

    // Build quorum pubkeys array string
    char quorumArray[MAX_QUORUM_SIZE * (PUBKEY_SIZE * 2 + 4) + 8] = "[";
    for (int i = 0; i < quorumSize; i++) {
        char hex[PUBKEY_SIZE * 2 + 1];
        bytesToHex(quorumPubKeys[i], PUBKEY_SIZE, hex);
        if (i > 0) strlcat(quorumArray, ",", sizeof(quorumArray));
        strlcat(quorumArray, "\"", sizeof(quorumArray));
        strlcat(quorumArray, hex,  sizeof(quorumArray));
        strlcat(quorumArray, "\"", sizeof(quorumArray));
    }
    strlcat(quorumArray, "]", sizeof(quorumArray));

    // Static buffer — this function is called once per event
    static char unsignedBody[2048];
    int bodyLen = snprintf(unsignedBody, sizeof(unsignedBody),
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"timestamp_ms\":%lu,"
        "\"quorum_auditor_pubkeys\":%s"
        "}",
        transporterHex,
        confidence,
        (unsigned long)ts,
        quorumArray
    );

    if (bodyLen <= 0 || (size_t)bodyLen >= sizeof(unsignedBody)) {
        Serial.println("[GW] ERROR: Anomaly claim body too large.");
        return false;
    }

    // ---- Sign the body ----
    uint8_t sig[SIG_SIZE];
    if (!signPayload((const uint8_t*)unsignedBody, (size_t)bodyLen, sig)) {
        Serial.println("[GW] ERROR: Signing anomaly claim failed.");
        return false;
    }

    char sigHex[SIG_SIZE * 2 + 1];
    bytesToHex(sig, SIG_SIZE, sigHex);

    // ---- Build final JSON (body + signature) ----
    static char finalJson[2176];
    int finalLen = snprintf(finalJson, sizeof(finalJson),
        "{"
        "\"transporter_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"timestamp_ms\":%lu,"
        "\"quorum_auditor_pubkeys\":%s,"
        "\"submission_signature\":\"%s\""
        "}",
        transporterHex,
        confidence,
        (unsigned long)ts,
        quorumArray,
        sigHex
    );

    if (finalLen <= 0) {
        Serial.println("[GW] ERROR: Final claim JSON build failed.");
        return false;
    }

    // ---- POST to relay ----
    WiFiClient relay;
    if (!relay.connect(FLOW_RELAY_IP, FLOW_RELAY_PORT)) {
        Serial.printf("[GW] ERROR: Cannot connect to relay at %s:%d\n",
                      FLOW_RELAY_IP, FLOW_RELAY_PORT);
        return false;
    }

    relay.printf("POST /anomaly HTTP/1.1\r\n");
    relay.printf("Host: %s\r\n", FLOW_RELAY_IP);
    relay.printf("Content-Type: application/json\r\n");
    relay.printf("Content-Length: %d\r\n", finalLen);
    relay.printf("Connection: close\r\n\r\n");
    relay.print(finalJson);

    // Wait for response (up to 5s)
    uint32_t deadline = millis() + 5000;
    while (!relay.available() && millis() < deadline) delay(10);

    String statusLine = relay.readStringUntil('\n');
    statusLine.trim();
    relay.stop();

    bool ok = statusLine.indexOf("200") >= 0;
    if (ok)
        Serial.println("[GW] Anomaly claim accepted by relay.");
    else
        Serial.printf("[GW] Relay rejected claim: %s\n", statusLine.c_str());

    return ok;
}
