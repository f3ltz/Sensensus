#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <config.h>

struct IMUSample {
    float ax;
    float ay;
    float az;
    float q_r, q_i, q_j, q_k;
    uint32_t timestampMs;
};

extern IMUSample g_sampleWindow[WINDOW_SIZE_SAMPLES];
extern int       g_windowHead;
extern bool      g_windowFull;

bool imu_init();

void imu_update();

bool imu_shouldSample();

IMUSample imu_getLatest();

void imu_flattenWindow(float outBuffer[INPUT_TENSOR_SIZE]);

size_t imu_buildCSVBuffer(char* outCSV, size_t maxLen);