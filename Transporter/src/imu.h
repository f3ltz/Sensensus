#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "config.h"

struct ImuSample {
    uint32_t timestamp_ms;
    float ax, ay, az;        // gravity-compensated linear accel (SH2_LINEAR_ACCELERATION)
    float qw, qx, qy, qz;   // unit quaternion (SH2_ROTATION_VECTOR)
};

// Call once. Returns true on success.
bool imu_init();

// Call every 20 ms from main loop. Reads one BNO085 report into both ring buffers.
void imu_update();

// Flatten g_sampleWindow[WINDOW_SIZE_SAMPLES] → float[INPUT_TENSOR_SIZE].
// Column order: ax,ay,az,qw,qx,qy,qz per sample row.
void imu_flattenWindow(float *out);

// Serialise csvRing[CSV_BUFFER_SAMPLES] → UTF-8 CSV string in buf (must be ≥ 8192 bytes).
void imu_buildCsvBuffer(char *buf, size_t buf_size);

// Expose last quaternion for payload building
extern ImuSample g_lastSample;