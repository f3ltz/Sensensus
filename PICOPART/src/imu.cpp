#include "imu.h"

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_BNO08x.h>
#include <stdio.h>
#include <string.h>

#define SDA_PIN 4
#define SCL_PIN 5

Adafruit_BNO08x bno08x;
static sh2_SensorValue_t sensorValue;
static uint32_t lastSampleMs = 0;
static IMUSample latestSample = {};

IMUSample g_sampleWindow[WINDOW_SIZE_SAMPLES];
int       g_windowHead = 0;
bool      g_windowFull = false;

static IMUSample CSVRing[CSV_BUFFER_SAMPLES];
static int       CSVHead = 0;
static bool      CSVFull = false;

bool imu_init() {
    Wire.setSDA(SDA_PIN);
    Wire.setSCL(SCL_PIN);
    Wire.begin();
    Wire.setClock(400000);

    if(!bno08x.begin_I2C(0x4A, &Wire)) {
        Serial.println("[IMU] ERROR: BNO085 not detected, Check wiring.");
        return false;
    }

    bno08x.enableReport(SH2_LINEAR_ACCELERATION, SAMPLE_INTERVAL_MS * 1000);
    bno08x.enableReport(SH2_ROTATION_VECTOR, SAMPLE_INTERVAL_MS * 1000);
    Serial.println("[IMU] BNO085 online.");
    return true;
}

bool imu_shouldSample() {
    uint32_t now = millis();
    return (now - lastSampleMs) >= SAMPLE_INTERVAL_MS;
}

void imu_update() {
    if (!bno08x.getSensorEvent(&sensorValue)) return;  // no new data

    latestSample.timestampMs = millis();

    if (sensorValue.sensorId == SH2_LINEAR_ACCELERATION) {
        latestSample.ax = sensorValue.un.linearAcceleration.x;
        latestSample.ay = sensorValue.un.linearAcceleration.y;
        latestSample.az = sensorValue.un.linearAcceleration.z;

        // Only push to windows on linear-acceleration reports so the
        // inference window has a uniform sample rate.
        g_sampleWindow[g_windowHead] = latestSample;
        g_windowHead = (g_windowHead + 1) % WINDOW_SIZE_SAMPLES;
        if (g_windowHead == 0) g_windowFull = true;

        CSVRing[CSVHead] = latestSample;
        CSVHead = (CSVHead + 1) % CSV_BUFFER_SAMPLES;
        if (CSVHead == 0) CSVFull = true;

        lastSampleMs = latestSample.timestampMs;

    } else if (sensorValue.sensorId == SH2_ROTATION_VECTOR) {
        latestSample.q_r = sensorValue.un.rotationVector.real;
        latestSample.q_i = sensorValue.un.rotationVector.i;
        latestSample.q_j = sensorValue.un.rotationVector.j;
        latestSample.q_k = sensorValue.un.rotationVector.k;
        // Quaternion updates don't trigger a window push — see above.
    }
}

IMUSample imu_getLatest() {
    return latestSample;
}

void imu_flattenWindow(float outBuffer[INPUT_TENSOR_SIZE]) {
    int outIdx = 0;
    // Start from the oldest sample: the slot right after head (full ring),
    // or slot 0 if the ring isn't full yet.
    int start = g_windowFull ? g_windowHead : 0;
    int count = g_windowFull ? WINDOW_SIZE_SAMPLES : g_windowHead;

    for (int i = 0; i < count; i++) {
        int srcIdx = (start + i) % WINDOW_SIZE_SAMPLES;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].ax;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].ay;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].az;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].q_i;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].q_j;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].q_k;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].q_r;
    }
    // Zero-pad if the window isn't full yet (first second of runtime).
    while (outIdx < INPUT_TENSOR_SIZE) {
        outBuffer[outIdx++] = 0.0f;
    }
}

size_t imu_buildCSVBuffer(char* outCSV, size_t maxLen) {
    size_t written = 0;

    // Header line
    int n = snprintf(outCSV, maxLen,
        "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n");
    if (n < 0 || (size_t)n >= maxLen) return written;
    written += n;

    int start = CSVFull ? CSVHead : 0;
    int count = CSVFull ? CSV_BUFFER_SAMPLES : CSVHead;

    for (int i = 0; i < count; i++) {
        int srcIdx = (start + i) % CSV_BUFFER_SAMPLES;
        const IMUSample& s = CSVRing[srcIdx];

        n = snprintf(outCSV + written, maxLen - written,
            "%lu,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
            (unsigned long)s.timestampMs,
            s.ax, s.ay, s.az,
            s.q_i, s.q_j, s.q_k, s.q_r);

        if (n < 0 || (written + n) >= maxLen) break;
        written += n;
    }

    return written;
}