#pragma once

// ============================================================
//  payload.h
//  Signed JSON payload builder — one payload per quorum auditor.
// ============================================================

#include <stdint.h>
#include <stddef.h>
#include "config.h"

#define PAYLOAD_MAX_SIZE 768

// Set by main.cpp each time infer_run() fires.
// payload_build() reads this — never hardcoded.
extern float g_lastConfidence;

/**
 * payload_build(auditorPubKey, outJson, maxLen)
 * Builds a signed JSON payload for a specific auditor.
 * Timestamp is captured once internally — no drift between
 * the signed body and the final output.
 * Returns bytes written, or 0 on failure.
 */
size_t payload_build(const uint8_t auditorPubKey[PUBKEY_SIZE],
                     char* outJson, size_t maxLen);
