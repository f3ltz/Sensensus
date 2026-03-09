#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

#define TENSOR_ARENA_SIZE (64 * 1024)

bool infer_init();

bool infer_run(const float inputData[INPUT_TENSOR_SIZE],
               float* outConfidence);