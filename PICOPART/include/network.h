#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "config.h"
#include "crypto.h"

#define MAX_AUDITORS 8

struct AuditorRecord {
    uint8_t  publicKey[PUBKEY_SIZE];  // verified ECDSA public key
    char     ipAddress[16];           // "x.x.x.x" string
    uint16_t port;                    // the port their beacon came from
    uint32_t lastSeenMs;              // millis() of last valid beacon
    bool     active;                  // slot in use?
};

extern AuditorRecord g_auditorRegistry[MAX_AUDITORS];
extern int g_auditorCount;

extern uint8_t g_winningAuditorPubKey[PUBKEY_SIZE];
extern bool    g_hasWinner;

bool net_init();

void net_handleUdp();

void net_handleHttp();

void net_broadcastAnomaly(float confidence);

const char* net_getLocalIp();
