#pragma once

// ============================================================
//  config.h
//  Central place for every tunable constant in the system.
//  Values marked BUILD_FLAG are injected via platformio.ini
//  build_flags so secrets never live in source control.
// ============================================================

// ---------- Wi-Fi (BUILD_FLAG) ----------
#ifndef WIFI_SSID
  #define WIFI_SSID "YOUR_SSID"
#endif
#ifndef WIFI_PASS
  #define WIFI_PASS "YOUR_PASSWORD"
#endif

// ---------- Network topology ----------
#ifndef MULTICAST_IP
  #define MULTICAST_IP "239.0.0.1"
#endif
#ifndef MULTICAST_PORT
  #define MULTICAST_PORT 5005
#endif
#ifndef HTTP_PORT
  #define HTTP_PORT 8080
#endif

// ---------- IMU / Inference ----------
#ifndef SAMPLE_RATE_HZ
  #define SAMPLE_RATE_HZ 50
#endif
// One sliding window fed into the CNN = 1 second of data
#ifndef WINDOW_SIZE_SAMPLES
  #define WINDOW_SIZE_SAMPLES 50
#endif
// 7 channels × window size = flat input tensor length
// Channels: ax, ay, az, qw, qx, qy, qz — ORDER FIXED, must match Asrith's training script
#define INPUT_TENSOR_SIZE (WINDOW_SIZE_SAMPLES * 7)

// Confidence score from the model above which we call it a drop
#ifndef ANOMALY_CONFIDENCE_THRESHOLD
  #define ANOMALY_CONFIDENCE_THRESHOLD 0.85f
#endif

// ---------- CSV buffer ----------
// 1.5 seconds worth of samples held in RAM for x402 serving
#define CSV_BUFFER_SAMPLES (SAMPLE_RATE_HZ + SAMPLE_RATE_HZ / 2)

// ---------- Crypto ----------
// micro-ecc curve — secp256r1 (NIST P-256)
// SHA-256 digest is 32 bytes; ECDSA sig on P-256 is 64 bytes
#define HASH_SIZE    32
#define SIG_SIZE     64
#define PUBKEY_SIZE  64   // uncompressed: 32-byte X + 32-byte Y
#define PRIVKEY_SIZE 32

// ---------- Timing ----------
#define SAMPLE_INTERVAL_MS   (1000 / SAMPLE_RATE_HZ)
#define ANOMALY_COOLDOWN_MS  5000   // don't re-broadcast within 5s of a drop
#define BID_COLLECTION_MS    500    // collect bids for 500ms before selecting quorum
#define DELIVERY_TIMEOUT_MS  15000  // max time to serve all quorum auditors

// ---------- Swarm / Quorum ----------
#define MAX_AUDITORS    8
#define MAX_QUORUM_SIZE 4   // top N bidders selected by staked FLOW balance
