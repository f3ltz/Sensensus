// ============================================================
//  main.cpp
//  Transporter node state machine.
//
//  States:
//    IDLE       — sampling + listening for beacons
//    ANOMALY    — drop detected, collecting bids for 500ms
//    DELIVERING — quorum notified, serving x402 to all winners
//
//  What the Pico does NOT do:
//    - Collect verdicts (auditors post directly to Flow)
//    - Run consensus (Flow contract runs it on-chain)
//    - Upload to Storacha (top-ranked auditor does this)
//
//  After DELIVERING, the Pico posts its own signed anomaly claim
//  to Flow via the relay, then returns to IDLE. That's it.
// ============================================================

#include <Arduino.h>
#include "config.h"
#include "crypto.h"
#include "imu.h"
#include "inference.h"
#include "network.h"
#include "payload.h"
#include "gateway.h"

// ---- State machine ----
enum class State { IDLE, ANOMALY, DELIVERING };
static State systemState = State::IDLE;

// ---- Timing ----
static uint32_t lastAnomalyMs    = 0;
static uint32_t anomalyStartMs   = 0;
static uint32_t deliveryStartMs  = 0;
static uint32_t lastInferenceMs  = 0;

#define INFERENCE_INTERVAL_MS 1000

// ============================================================
//  setup
// ============================================================
void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("\n[MAIN] ===== Pico 2W Transporter Booting =====");

    if (!generateKeyPair()) {
        Serial.println("[MAIN] FATAL: Key generation failed.");
        while (true) delay(1000);
    }
    if (!imu_init()) {
        Serial.println("[MAIN] FATAL: IMU init failed.");
        while (true) delay(1000);
    }
    if (!infer_init()) {
        Serial.println("[MAIN] FATAL: Inference init failed.");
        while (true) delay(1000);
    }
    if (!net_init()) {
        Serial.println("[MAIN] FATAL: Network init failed.");
        while (true) delay(1000);
    }

    Serial.printf("[MAIN] x402 endpoint: http://%s:%d/data\n",
                  net_getLocalIp(), HTTP_PORT);
    Serial.println("[MAIN] Boot complete.\n");
}

// ============================================================
//  loop
// ============================================================
void loop() {
    uint32_t now = millis();

    // ---- IMU sampling: every 20ms regardless of state ----
    if (imu_shouldSample()) imu_update();

    // ---- UDP: always running ----
    net_handleUdp();

    // ---- HTTP: always running ----
    net_handleHttp();

    // ==========================================================
    //  STATE: IDLE
    //  Run inference every second. On drop detection, broadcast
    //  anomaly and start collecting bids.
    // ==========================================================
    if (systemState == State::IDLE) {
        bool cooldown  = (now - lastAnomalyMs) >= ANOMALY_COOLDOWN_MS;
        bool inferDue  = g_windowFull &&
                         (now - lastInferenceMs) >= INFERENCE_INTERVAL_MS;

        if (inferDue && cooldown) {
            lastInferenceMs = now;

            float inputData[INPUT_TENSOR_SIZE];
            imu_flattenWindow(inputData);

            float confidence = 0.0f;
            if (infer_run(inputData, &confidence)) {
                // Always update g_lastConfidence so payload_build() has it
                g_lastConfidence = confidence;

                if (confidence >= ANOMALY_CONFIDENCE_THRESHOLD) {
                    Serial.printf("[MAIN] DROP! Confidence: %.3f\n", confidence);
                    lastAnomalyMs  = now;
                    anomalyStartMs = now;
                    systemState    = State::ANOMALY;
                    net_broadcastAnomaly(confidence);
                }
            }
        }
    }

    // ==========================================================
    //  STATE: ANOMALY
    //  Collect bids for BID_COLLECTION_MS, then select quorum
    //  and send PKT_QUORUM to each winner.
    // ==========================================================
    else if (systemState == State::ANOMALY) {
        if ((now - anomalyStartMs) >= BID_COLLECTION_MS) {
            if (g_bidCount == 0) {
                Serial.println("[MAIN] No bids received — back to IDLE.");
                net_resetEvent();
                systemState = State::IDLE;
            } else {
                net_selectQuorumAndNotify();
                deliveryStartMs = now;
                systemState     = State::DELIVERING;
            }
        }
    }

    // ==========================================================
    //  STATE: DELIVERING
    //  HTTP server handles x402 for each quorum auditor.
    //  Once all are served (or timeout), post anomaly claim
    //  to Flow and return to IDLE.
    // ==========================================================
    else if (systemState == State::DELIVERING) {
        bool allDone  = net_allQuorumServed();
        bool timedOut = (now - deliveryStartMs) >= DELIVERY_TIMEOUT_MS;

        if (allDone || timedOut) {
            if (timedOut && !allDone)
                Serial.printf("[MAIN] Delivery timeout. Served %d/%d auditors.\n",
                              g_servedCount, g_quorumSize);
            else
                Serial.println("[MAIN] All quorum auditors served.");

            // ---- Post Pico's anomaly claim to Flow relay ----
            // Gather quorum pubkeys for the submission
            uint8_t quorumKeys[MAX_QUORUM_SIZE][PUBKEY_SIZE];
            int     keyCount = 0;
            for (int i = 0; i < MAX_AUDITORS && keyCount < g_quorumSize; i++) {
                if (g_auditorRegistry[i].active && g_auditorRegistry[i].inQuorum) {
                    memcpy(quorumKeys[keyCount], g_auditorRegistry[i].publicKey, PUBKEY_SIZE);
                    keyCount++;
                }
            }

            bool flowOk = gateway_postAnomalyClaim(g_lastConfidence,
                                                    quorumKeys, keyCount);
            if (!flowOk)
                Serial.println("[MAIN] WARNING: Flow submission failed. "
                               "Auditors can still submit verdicts independently.");

            // Reset and return to IDLE
            net_resetEvent();
            systemState = State::IDLE;
            Serial.println("[MAIN] Event complete — back to IDLE.\n");
        }
    }

    delay(1);  // yield to CYW43 Wi-Fi stack
}
