#pragma once

#include <stdint.h>
#include <stdbool.h>

#define PAYLOAD_MAX_SIZE 768

size_t payload_build(float confidence, char* outJson, size_t maxLen);

void payload_printSerial(const char* json);
