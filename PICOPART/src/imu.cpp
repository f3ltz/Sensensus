#include "imu.h"
#include <Adafruit_BNO08x.h>
#include <Wire.h>
#include <Arduino.h>
#include <stdio.h>
#include <string.h>

#define BNO_SDA 4
#define BNO_SCL 5
#define BNO_ADDR 0x4A    // Adafruit BNO085 breakout default

static Adafruit_BNO08x bno(-1);   // no reset pin
static sh2_SensorValue_t _sensorVal;

// ── Ring buffers ──────────────────────────────────────────────────────────────
static ImuSample g_sampleWindow[WINDOW_SIZE_SAMPLES];  // 50-sample inference window
static ImuSample g_csvRing[CSV_BUFFER_SAMPLES];         // 75-sample payload buffer
static int       g_windowHead = 0;
static int       g_csvHead    = 0;
static bool      g_windowFull = false;
static bool      g_csvFull    = false;

// Pending half-assembled sample (linear accel and quaternion come in separate reports)
static float     _pending_ax = 0, _pending_ay = 0, _pending_az = 0;
static float     _pending_qw = 1, _pending_qx = 0, _pending_qy = 0, _pending_qz = 0;
static bool      _have_accel = false, _have_quat = false;

ImuSample g_lastSample = {};

// ── Helper: commit a fully-assembled sample ───────────────────────────────────
static void _commit_sample() {
    uint32_t ts = millis();
    ImuSample s = { ts, _pending_ax, _pending_ay, _pending_az,
                    _pending_qw, _pending_qx, _pending_qy, _pending_qz };

    // Write into 50-sample inference window
    g_sampleWindow[g_windowHead] = s;
    g_windowHead = (g_windowHead + 1) % WINDOW_SIZE_SAMPLES;
    if (g_windowHead == 0) g_windowFull = true;

    // Write into 75-sample CSV ring
    g_csvRing[g_csvHead] = s;
    g_csvHead = (g_csvHead + 1) % CSV_BUFFER_SAMPLES;
    if (g_csvHead == 0) g_csvFull = true;

    g_lastSample = s;
    _have_accel = _have_quat = false;
}

// ── Init ──────────────────────────────────────────────────────────────────────
bool imu_init() {
    Wire.setSDA(BNO_SDA);
    Wire.setSCL(BNO_SCL);
    Wire.begin();

    if (!bno.begin_I2C(BNO_ADDR, &Wire)) {
        Serial.println("[IMU] BNO085 not found at 0x4B");
        return false;
    }

    // Enable linear acceleration (gravity-compensated) — NOT raw accelerometer
    if (!bno.enableReport(SH2_LINEAR_ACCELERATION, 1000000 / SAMPLE_RATE_HZ)) {
        Serial.println("[IMU] Failed to enable SH2_LINEAR_ACCELERATION");
        return false;
    }
    // Enable rotation vector (unit quaternion)
    if (!bno.enableReport(SH2_ROTATION_VECTOR, 1000000 / SAMPLE_RATE_HZ)) {
        Serial.println("[IMU] Failed to enable SH2_ROTATION_VECTOR");
        return false;
    }

    Serial.println("[IMU] BNO085 initialised at 50 Hz");
    return true;
}

// ── Update — call at 50 Hz ────────────────────────────────────────────────────
void imu_update() {
    while (bno.getSensorEvent(&_sensorVal)) {
        switch (_sensorVal.sensorId) {
            case SH2_LINEAR_ACCELERATION:
                _pending_ax   = _sensorVal.un.linearAcceleration.x;
                _pending_ay   = _sensorVal.un.linearAcceleration.y;
                _pending_az   = _sensorVal.un.linearAcceleration.z;
                _have_accel   = true;
                break;
            case SH2_ROTATION_VECTOR:
                _pending_qw   = _sensorVal.un.rotationVector.real;
                _pending_qx   = _sensorVal.un.rotationVector.i;
                _pending_qy   = _sensorVal.un.rotationVector.j;
                _pending_qz   = _sensorVal.un.rotationVector.k;
                _have_quat    = true;
                break;
        }
        // Commit once we have both in this sensor tick
        if (_have_accel && _have_quat) {
            _commit_sample();
        }
    }
}

// ── Flatten inference window → float[350] ─────────────────────────────────────
// Produces samples in chronological order regardless of ring buffer head position.
// Column order per row: ax, ay, az, qw, qx, qy, qz  (7 channels × 50 rows = 350)
void imu_flattenWindow(float *out) {
    int n = g_windowFull ? WINDOW_SIZE_SAMPLES : g_windowHead;
    // Pad zeros at front if window not full yet
    int zeros = WINDOW_SIZE_SAMPLES - n;
    memset(out, 0, zeros * 7 * sizeof(float));

    int start = g_windowFull ? g_windowHead : 0;
    for (int i = 0; i < n; i++) {
        int idx = (start + i) % WINDOW_SIZE_SAMPLES;
        float *row = out + (zeros + i) * 7;
        row[0] = g_sampleWindow[idx].ax;
        row[1] = g_sampleWindow[idx].ay;
        row[2] = g_sampleWindow[idx].az;
        row[3] = g_sampleWindow[idx].qw;
        row[4] = g_sampleWindow[idx].qx;
        row[5] = g_sampleWindow[idx].qy;
        row[6] = g_sampleWindow[idx].qz;
    }
}

// ── Build 75-row CSV ─────────────────────────────────────────────────────────
void imu_buildCsvBuffer(char *buf, size_t buf_size) {
    int n     = g_csvFull ? CSV_BUFFER_SAMPLES : g_csvHead;
    int start = g_csvFull ? g_csvHead : 0;

    int written = snprintf(buf, buf_size, "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n");
    for (int i = 0; i < n && written < (int)buf_size - 1; i++) {
        int idx = (start + i) % CSV_BUFFER_SAMPLES;
        const ImuSample &s = g_csvRing[idx];
        written += snprintf(buf + written, buf_size - written,
            "%lu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
            (unsigned long)s.timestamp_ms,
            s.ax, s.ay, s.az, s.qw, s.qx, s.qy, s.qz);
    }
}