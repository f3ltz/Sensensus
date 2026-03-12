#pragma once

// ============================================================
//  gateway.h
//  Outbound HTTP calls to the Flow blockchain.
//
//  The Pico submits ONLY its own anomaly claim — not verdicts,
//  not consensus results. Those are submitted directly by auditors.
//
//  Flow REST API endpoint (testnet):
//    https://rest-testnet.onflow.org/v1/transactions
//
//  NOTE ON TLS: The Flow REST API requires HTTPS. The Pico's
//  Arduino-Pico WiFiClientSecure supports TLS but requires the
//  server's root CA certificate to be embedded. For the hackathon
//  demo you have two options:
//    1. Use WiFiClientSecure with Flow's CA cert (proper)
//    2. Run a thin HTTP relay on a laptop that accepts plain HTTP
//       from the Pico and forwards to Flow over HTTPS (faster to build)
//  Option 2 is recommended for the hackathon timeline. The relay
//  is a 20-line Python script. This file implements option 2 —
//  it POSTs to FLOW_RELAY_URL which you run on your demo laptop.
// ============================================================

#include <stdint.h>
#include <stdbool.h>

// Set these in platformio.ini build_flags
#ifndef FLOW_RELAY_IP
  #define FLOW_RELAY_IP "192.168.1.100"  // IP of laptop running relay script
#endif
#ifndef FLOW_RELAY_PORT
  #define FLOW_RELAY_PORT 9090
#endif
#ifndef FLOW_CONTRACT_ADDRESS
  #define FLOW_CONTRACT_ADDRESS "0xYOUR_CONTRACT_ADDRESS"
#endif

/**
 * gateway_postAnomalyClaim(confidence, quorumPubKeys, quorumSize)
 * Posts the Pico's signed anomaly claim to the Flow relay.
 * Payload:
 *   {
 *     transporter_pubkey,
 *     anomaly_confidence,
 *     timestamp_ms,
 *     quorum_auditor_pubkeys[],
 *     submission_signature       ← ECDSA over all of the above
 *   }
 * The Flow contract verifies submission_signature against
 * transporter_pubkey to confirm this came from a real Pico.
 * Returns true if the relay accepted the request (HTTP 200).
 */
bool gateway_postAnomalyClaim(float confidence,
                               const uint8_t quorumPubKeys[][64],
                               int quorumSize);
