#pragma once

#ifndef WIFI_SSID
  #define WIFI_SSID "YOUR_SSID"
#endif
#ifndef WIFI_PASS
  #define WIFI_PASS "YOUR_PASSWORD"
#endif

#ifndef MULTICAST_IP
  #define MULTICAST_IP "239.0.0.1"
#endif
#ifndef MULTICAST_PORT
  #define MULTICAST_PORT 5005
#endif
#ifndef HTTP_PORT
  #define HTTP_PORT 8080
#endif

#ifndef SAMPLE_RATE_HZ
  #define SAMPLE_RATE_HZ 50
#endif

#ifndef WINDOW_SIZE_SAMPLES
  #define WINDOW_SIZE_SAMPLES 50
#endif

#define INPUT_TENSOR_SIZE (WINDOW_SIZE_SAMPLES * 7)  // 7 = ax, ay, az, q_r, q_i, q_j, q_k

#ifndef ANOMALY_CONFIDENCE_THRESHOLD
  #define ANOMALY_CONFIDENCE_THRESHOLD 0.85f
#endif

#define CSV_BUFFER_SAMPLES (SAMPLE_RATE_HZ + SAMPLE_RATE_HZ / 2)

#define HASH_SIZE    32
#define SIG_SIZE     64
#define PUBKEY_SIZE  64   // uncompressed: 32-byte X + 32-byte Y
#define PRIVKEY_SIZE 32

#define SAMPLE_INTERVAL_MS   (1000 / SAMPLE_RATE_HZ)
#define ANOMALY_COOLDOWN_MS  5000