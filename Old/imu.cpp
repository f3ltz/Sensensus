// ============================================================
//  imu.cpp
//  BNO085 driver implementation using the SparkFun library.
//
//  The BNO085 communicates over I2C (default address 0x4A).
//  SDA → GPIO4, SCL → GPIO5 on Pico W (Wire0 default pins).
//  If you wired to different pins, change Wire.setSDA/SCL below.
// ============================================================

#include "imu.h"
#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_BNO08x.h>
#include <stdio.h>
#include <string.h>

// ---- Module globals ----
static Adafruit_BNO08x imu;
static sh2_SensorValue_t sensorValue;   // Adafruit uses this struct for all reports
static uint32_t lastSampleMs = 0;
static ImuSample latestSample = {};

// Circular sample window — public, inference reads this directly.
ImuSample g_sampleWindow[WINDOW_SIZE_SAMPLES];
int       g_windowHead = 0;
bool      g_windowFull = false;

// Extended CSV ring buffer for the x402 payload (1.5 s of data).
static ImuSample csvRing[CSV_BUFFER_SAMPLES];
static int       csvHead = 0;
static bool      csvFull = false;

// ============================================================
//  imu_init
// ============================================================
bool imu_init() {
    // Configure I2C pins. Adjust if your wiring differs.
    Wire.setSDA(4);
    Wire.setSCL(5);
    Wire.begin();
    Wire.setClock(400000);  // 400 kHz fast mode

    // Adafruit_BNO08x::begin_I2C() defaults to address 0x4B.
    // If your breakout has ADR pulled LOW, pass BNO08x_I2CADDR_DEFAULT (0x4A).
    // Check the bottom of your Adafruit breakout for the ADR solder jumper.
    if (!imu.begin_I2C(BNO08x_I2CADDR_DEFAULT, &Wire)) {
        Serial.println("[IMU] ERROR: BNO085 not detected. Check wiring/address.");
        return false;
    }

    // Enable linear acceleration report (gravity-compensated).
    // Adafruit API: enableReport(reportId, intervalMicros)
    if (!imu.enableReport(SH2_LINEAR_ACCELERATION, 1000000 / SAMPLE_RATE_HZ)) {
        Serial.println("[IMU] ERROR: Could not enable linear acceleration report.");
        return false;
    }

    // Enable rotation vector (quaternion) for the 3D dashboard visualiser.
    if (!imu.enableReport(SH2_ROTATION_VECTOR, 1000000 / SAMPLE_RATE_HZ)) {
        Serial.println("[IMU] ERROR: Could not enable rotation vector report.");
        return false;
    }

    Serial.println("[IMU] BNO085 online.");
    return true;
}

// ============================================================
//  imu_shouldSample
// ============================================================
bool imu_shouldSample() {
    uint32_t now = millis();
    return (now - lastSampleMs) >= SAMPLE_INTERVAL_MS;
}

// ============================================================
//  imu_update
//  Reads one report from the BNO085 and pushes it into both
//  the inference window and the CSV ring buffer.
//
//  Adafruit API difference from SparkFun:
//  Instead of separate getLinAccelX()/getQuatReal() calls,
//  getSensorEvent() fills a sh2_SensorValue_t struct and you
//  check sensorValue.sensorId to know which report arrived,
//  then read from the appropriate union field.
// ============================================================
void imu_update() {
    if (!imu.getSensorEvent(&sensorValue)) return;  // no new data

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

        csvRing[csvHead] = latestSample;
        csvHead = (csvHead + 1) % CSV_BUFFER_SAMPLES;
        if (csvHead == 0) csvFull = true;

        lastSampleMs = latestSample.timestampMs;

    } else if (sensorValue.sensorId == SH2_ROTATION_VECTOR) {
        latestSample.qw = sensorValue.un.rotationVector.real;
        latestSample.qx = sensorValue.un.rotationVector.i;
        latestSample.qy = sensorValue.un.rotationVector.j;
        latestSample.qz = sensorValue.un.rotationVector.k;
        // Quaternion updates don't trigger a window push — see above.
    }
}

// ============================================================
//  imu_getLatest
// ============================================================
ImuSample imu_getLatest() {
    return latestSample;
}

// ============================================================
//  imu_flattenWindow
//  Unrolls the circular window into a contiguous float array
//  in chronological order so the TFLite input tensor always
//  sees samples oldest → newest, regardless of where g_windowHead
//  currently sits in the ring.
// ============================================================
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
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].qw;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].qx;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].qy;
        outBuffer[outIdx++] = g_sampleWindow[srcIdx].qz;
    }
    // Zero-pad if the window isn't full yet (first second of runtime).
    while (outIdx < INPUT_TENSOR_SIZE) {
        outBuffer[outIdx++] = 0.0f;
    }
}

// ============================================================
//  imu_buildCsvBuffer
//  Serialises the CSV ring into a response body string.
//  The Auditor's Model B needs timestamped columns to align
//  its random-forest features correctly.
// ============================================================
size_t imu_buildCsvBuffer(char* outCsv, size_t maxLen) {
    size_t written = 0;

    // Header line
    int n = snprintf(outCsv, maxLen,
        "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n");
    if (n < 0 || (size_t)n >= maxLen) return written;
    written += n;

    int start = csvFull ? csvHead : 0;
    int count = csvFull ? CSV_BUFFER_SAMPLES : csvHead;

    for (int i = 0; i < count; i++) {
        int srcIdx = (start + i) % CSV_BUFFER_SAMPLES;
        const ImuSample& s = csvRing[srcIdx];

        n = snprintf(outCsv + written, maxLen - written,
            "%lu,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
            (unsigned long)s.timestampMs,
            s.ax, s.ay, s.az,
            s.qw, s.qx, s.qy, s.qz);

        if (n < 0 || (written + n) >= maxLen) break;
        written += n;
    }

    return written;
}
