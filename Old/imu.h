#pragma once

// ============================================================
//  imu.h
//  Interface for the BNO085 IMU over I2C.
//
//  The BNO085 is a "sensor fusion" IMU — it runs its own
//  internal Kalman filter and gives you calibrated orientation
//  quaternions and linear acceleration vectors directly, so you
//  don't need to implement sensor fusion yourself on the Pico.
//
//  For drop detection we use the LINEAR_ACCELERATION report,
//  which strips out gravity. A free-fall drop will produce near-
//  zero linear acceleration on all axes, followed by a sharp
//  spike on impact. That signature is what the CNN is trained to
//  recognize in a 50-sample (1-second) sliding window.
// ============================================================

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

// A single timestamped IMU reading.
struct ImuSample {
    float ax;           // linear acceleration X (m/s²)
    float ay;           // linear acceleration Y
    float az;           // linear acceleration Z
    float qw, qx, qy, qz;  // orientation quaternion (for 3D dashboard viz)
    uint32_t timestampMs;
};

// A fixed-size sliding window of raw samples, filled by imu_update().
// The inference module reads directly from this buffer.
extern ImuSample g_sampleWindow[WINDOW_SIZE_SAMPLES];
extern int       g_windowHead;    // index of the most recent sample
extern bool      g_windowFull;    // false until the first full window is ready

// ---- Lifecycle ----

/**
 * imu_init()
 * Initialises I2C and configures the BNO085 to report:
 *   - Linear acceleration at SAMPLE_RATE_HZ
 *   - Rotation vector (quaternion) at SAMPLE_RATE_HZ
 * Returns true on success. Will halt with a serial error if the
 * sensor isn't detected — check wiring if this happens.
 */
bool imu_init();

/**
 * imu_update()
 * Must be called every loop() iteration. Reads any pending reports
 * from the BNO085 and pushes them into g_sampleWindow as a circular
 * buffer. Call imu_shouldSample() first to respect timing.
 */
void imu_update();

/**
 * imu_shouldSample()
 * Returns true when enough time has elapsed since the last sample
 * to maintain SAMPLE_RATE_HZ. Use this to gate imu_update() calls
 * so you don't spin-poll the sensor and waste cycles.
 */
bool imu_shouldSample();

/**
 * imu_getLatest()
 * Returns the most recently read sample without advancing the window.
 * Safe to call from anywhere — e.g., to update the 3D dashboard.
 */
ImuSample imu_getLatest();

/**
 * imu_flattenWindow(outBuffer)
 * Flattens g_sampleWindow into a contiguous float array suitable
 * for feeding directly into the TFLite input tensor.
 * Layout: [ax0, ay0, az0, ax1, ay1, az1, ..., axN, ayN, azN]
 * outBuffer must be INPUT_TENSOR_SIZE floats (defined in config.h).
 */
void imu_flattenWindow(float outBuffer[INPUT_TENSOR_SIZE]);

/**
 * imu_buildCsvBuffer(outCsv, maxLen)
 * Serialises the last CSV_BUFFER_SAMPLES samples into a comma-
 * separated string for the x402 HTTP response body.
 * Format per line: "timestamp_ms,ax,ay,az,qw,qx,qy,qz\n"
 * Returns the number of characters written.
 */
size_t imu_buildCsvBuffer(char* outCsv, size_t maxLen);
