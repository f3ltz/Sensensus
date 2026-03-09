#include <Arduino.h>
#include "config.h"
#include "crypto.h"
#include "imu.h"
#include "inference.h"
#include "network.h"
#include "payload.h"

enum class State {
    IDLE,
    ANOMALY,
    DELIVERING
};

static State systemState = State::IDLE;

static uint32_t lastAnomalyMs = 0;

static uint32_t lastInferenceMs = 0;
#define INFERENCE_INTERVAL_MS 1000

static uint32_t anomalyBroadcastMs = 0;
#define BID_TIMEOUT_MS 10000

static char finalPayloadJson[PAYLOAD_MAX_SIZE];

void setup() {
    Serial.begin(115200);
    delay(2000);  // Give the serial monitor time to connect
    Serial.println("\n[MAIN] ===== Pico 2W Transporter Node Booting =====");

    // ---- Step 1: Crypto identity ----
    // This must run before net_init() because the network layer
    // signs outbound packets using g_privateKey from the start.
    Serial.println("[MAIN] Generating ECDSA key pair...");
    if (!generateKeyPair()) {
        Serial.println("[MAIN] FATAL: Key generation failed. Halting.");
        while (true) delay(1000);
    }

    // ---- Step 2: IMU ----
    Serial.println("[MAIN] Initialising BNO085 IMU...");
    if (!imu_init()) {
        Serial.println("[MAIN] FATAL: IMU init failed. Halting.");
        while (true) delay(1000);
    }

    // ---- Step 3: TFLite Micro inference engine ----
    // This must run after IMU init because it validates INPUT_TENSOR_SIZE,
    // which depends on WINDOW_SIZE_SAMPLES defined in config.h.
    Serial.println("[MAIN] Loading TFLite Micro model...");
    if (!infer_init()) {
        Serial.println("[MAIN] FATAL: Inference init failed. Halting.");
        while (true) delay(1000);
    }
    
    // ---- Step 4: Networking ----
    Serial.println("[MAIN] Starting network...");
    if (!net_init()) {
        Serial.println("[MAIN] FATAL: Network init failed. Halting.");
        while (true) delay(1000);
    }

    // Print the x402 endpoint URL so you can test with curl during dev.
    Serial.print("[MAIN] x402 endpoint: http://");
    Serial.print(net_getLocalIp());
    Serial.print(":");
    Serial.print(HTTP_PORT);
    Serial.println("/data");

    Serial.println("[MAIN] Boot complete. Entering main loop.");
    Serial.println("[MAIN] =========================================\n");
}

void loop() {
    uint32_t now = millis();
    
    // ============================================================
    //  TASK A: IMU Sampling
    //  Runs at SAMPLE_RATE_HZ (50 Hz = every 20 ms).
    //  The imu_update() function pushes each sample into the
    //  circular window and the CSV ring buffer.
    // ============================================================
    if (imu_shouldSample()) {
        imu_update();
    }

    // ============================================================
    //  TASK B: TFLite Inference
    //  Runs every INFERENCE_INTERVAL_MS (1 second) once the
    //  window is full. We wait for a full window so the model
    //  always gets a complete 50-sample input; partial windows
    //  would produce unreliable confidence scores.
    // ============================================================
    bool cooldownElapsed = (now - lastAnomalyMs) >= ANOMALY_COOLDOWN_MS;
    bool inferenceReady  = g_windowFull &&
                           (now - lastInferenceMs) >= INFERENCE_INTERVAL_MS;

    if (inferenceReady && systemState == State::IDLE && cooldownElapsed) {
        lastInferenceMs = now;

        // Flatten the circular window into a contiguous float array.
        float inputData[INPUT_TENSOR_SIZE];
        imu_flattenWindow(inputData);

        float confidence = 0.0f;
        bool  ok = infer_run(inputData, &confidence);

        if (ok && confidence >= ANOMALY_CONFIDENCE_THRESHOLD) {
            Serial.print("[MAIN] DROP DETECTED! Confidence: ");
            Serial.println(confidence, 3);

            // Transition to ANOMALY state and broadcast the event.
            systemState = State::ANOMALY;
            lastAnomalyMs = now;
            anomalyBroadcastMs = now;

            net_broadcastAnomaly(confidence);
        }
    }

    // ============================================================
    //  TASK C: UDP Handler
    //  Processes incoming Auditor beacons and bids.
    //  All signature verification happens inside net_handleUdp().
    //  If a valid bid arrives, net_handleUdp() sets g_hasWinner = true
    //  and copies the winning key into g_winningAuditorPubKey.
    // ============================================================
    net_handleUdp();

    // Check whether a winner has arrived during the ANOMALY state.
    if (systemState == State::ANOMALY) {
        if (g_hasWinner) {
            Serial.println("[MAIN] Winner set — transitioning to DELIVERING.");
            systemState = State::DELIVERING;

            // Build and print the signed payload for the Gateway.
            // The Gateway script reads this from serial and parses
            // the JSON to submit to the Flow contract.
            size_t len = payload_build(
                /* confidence */ 0.0f,  // TODO: persist confidence from infer_run
                finalPayloadJson,
                sizeof(finalPayloadJson)
            );
            if (len > 0) {
                payload_printSerial(finalPayloadJson);
            }

        } else if ((now - anomalyBroadcastMs) > BID_TIMEOUT_MS) {
            // No bid arrived within the timeout window.
            Serial.println("[MAIN] Bid timeout — returning to IDLE.");
            systemState = State::IDLE;
            g_hasWinner = false;
        }
    }

    // After delivery, reset state so the next drop event starts fresh.
    if (systemState == State::DELIVERING) {
        // The HTTP server (Task D) handles the actual CSV transfer.
        // Once the server has served the data it doesn't need to signal
        // back here — the DELIVERING state just means the HTTP endpoint
        // is armed and ready. We return to IDLE after a short delay to
        // allow the Auditor to complete its GET /data → POST /pay cycle.
        // In a production system you'd have the HTTP handler explicitly
        // set a "served" flag; for the hackathon a fixed window is fine.
        if ((now - anomalyBroadcastMs) > (BID_TIMEOUT_MS + 15000)) {
            Serial.println("[MAIN] Delivery window closed — returning to IDLE.");
            systemState = State::IDLE;
            g_hasWinner = false;
            memset(g_winningAuditorPubKey, 0, PUBKEY_SIZE);
        }
    }

    // ============================================================
    //  TASK D: HTTP x402 Server
    //  Handles client connections for the CSV data endpoint.
    //  This is non-blocking — returns immediately if no client is
    //  pending, so it doesn't stall the IMU or inference tasks.
    // ============================================================
    net_handleHttp();

    // A tiny yield delay (1 ms) gives the CYW43 Wi-Fi chip time to
    // process its internal event queue. Without this, the TCP/IP stack
    // can starve when the main loop runs very tight. This is a known
    // requirement for the Arduino-Pico framework's Wi-Fi driver.
    delay(1);
}