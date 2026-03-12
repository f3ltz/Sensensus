// ============================================================
//  network.cpp
// ============================================================

#include "network.h"
#include "imu.h"
#include "payload.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <string.h>
#include <stdio.h>
#include "pico/rand.h"

// ---- Module state ----
static WiFiUDP    udpSocket;
static WiFiServer httpServer(HTTP_PORT);

AuditorRecord g_auditorRegistry[MAX_AUDITORS] = {};
int           g_auditorCount = 0;

BidRecord g_bidPool[MAX_AUDITORS] = {};
int       g_bidCount    = 0;
int       g_quorumSize  = 0;
int       g_servedCount = 0;

// Per-auditor nonce table for x402 (one nonce per quorum slot)
static uint8_t  invoiceNonces[MAX_AUDITORS][16] = {};
static bool     noncePending[MAX_AUDITORS]       = {};

static uint8_t udpBuf[256];

// ============================================================
//  net_init
// ============================================================
bool net_init() {
    Serial.print("[NET] Connecting to Wi-Fi");
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
        if (millis() - start > 20000) {
            Serial.println("\n[NET] ERROR: Wi-Fi timed out.");
            return false;
        }
    }
    Serial.print("\n[NET] Connected. IP: ");
    Serial.println(WiFi.localIP());

    IPAddress multicastGroup;
    multicastGroup.fromString(MULTICAST_IP);
    udpSocket.beginMulticast(WiFi.localIP(), multicastGroup, MULTICAST_PORT);
    Serial.printf("[NET] UDP multicast %s:%d\n", MULTICAST_IP, MULTICAST_PORT);

    httpServer.begin();
    Serial.printf("[NET] HTTP server on port %d\n", HTTP_PORT);
    return true;
}

// ============================================================
//  Internal helpers
// ============================================================
static AuditorRecord* findOrAddAuditor(const uint8_t pubKey[PUBKEY_SIZE],
                                        const char* ip, uint16_t port) {
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (g_auditorRegistry[i].active &&
            memcmp(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE) == 0)
            return &g_auditorRegistry[i];
    }
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (!g_auditorRegistry[i].active) {
            memcpy(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE);
            strncpy(g_auditorRegistry[i].ipAddress, ip, 15);
            g_auditorRegistry[i].port      = port;
            g_auditorRegistry[i].active    = true;
            g_auditorRegistry[i].inQuorum  = false;
            g_auditorRegistry[i].served    = false;
            g_auditorCount++;
            char hex[17]; bytesToHex(pubKey, 8, hex); hex[16] = '\0';
            Serial.printf("[NET] Auditor registered: %s... from %s\n", hex, ip);
            return &g_auditorRegistry[i];
        }
    }
    Serial.println("[NET] WARNING: Auditor registry full.");
    return nullptr;
}

static bool isRegistered(const uint8_t pubKey[PUBKEY_SIZE]) {
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (g_auditorRegistry[i].active &&
            memcmp(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE) == 0)
            return true;
    }
    return false;
}

static AuditorRecord* findInRegistry(const uint8_t pubKey[PUBKEY_SIZE]) {
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (g_auditorRegistry[i].active &&
            memcmp(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE) == 0)
            return &g_auditorRegistry[i];
    }
    return nullptr;
}

static int registryIndexForIp(const char* ip) {
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (g_auditorRegistry[i].active &&
            g_auditorRegistry[i].inQuorum &&
            strcmp(g_auditorRegistry[i].ipAddress, ip) == 0)
            return i;
    }
    return -1;
}

// ============================================================
//  net_handleUdp
//  Sybil gate on every packet. Bids also checked against registry.
// ============================================================
void net_handleUdp() {
    int packetSize = udpSocket.parsePacket();
    if (packetSize <= 0) return;

    if (packetSize > (int)sizeof(udpBuf)) {
        Serial.println("[NET] Oversized packet — dropped.");
        udpSocket.flush();
        return;
    }

    int bytesRead = udpSocket.read(udpBuf, sizeof(udpBuf));
    if (bytesRead < (int)PKT_SIGNED_SIZE) {
        Serial.println("[NET] Undersized packet — dropped.");
        return;
    }

    uint8_t          pktType      = udpBuf[0];
    const uint8_t*   senderPubKey = &udpBuf[1];
    const uint8_t*   signature    = &udpBuf[PKT_HEADER_SIZE];

    // ---- SYBIL GATE ----
    if (!verifySignature(udpBuf, PKT_HEADER_SIZE, signature, senderPubKey)) {
        Serial.printf("[NET] REJECTED invalid sig from %s\n",
                      udpSocket.remoteIP().toString().c_str());
        return;
    }

    char     senderIp[16];
    uint16_t senderPort = udpSocket.remotePort();
    udpSocket.remoteIP().toString().toCharArray(senderIp, sizeof(senderIp));

    if (pktType == PKT_BEACON) {
        AuditorRecord* rec = findOrAddAuditor(senderPubKey, senderIp, senderPort);
        if (rec) rec->lastSeenMs = millis();

    } else if (pktType == PKT_BID) {
        // ---- REGISTRY GATE: must have beaconed first ----
        if (!isRegistered(senderPubKey)) {
            Serial.printf("[NET] Bid from unregistered auditor %s — dropped.\n", senderIp);
            return;
        }
        // Deduplicate — ignore repeat bids from same key
        for (int i = 0; i < g_bidCount; i++) {
            if (memcmp(g_bidPool[i].publicKey, senderPubKey, PUBKEY_SIZE) == 0)
                return;
        }
        if (g_bidCount < MAX_AUDITORS) {
            memcpy(g_bidPool[g_bidCount].publicKey, senderPubKey, PUBKEY_SIZE);
            strncpy(g_bidPool[g_bidCount].ipAddress, senderIp, 15);
            g_bidPool[g_bidCount].port = senderPort;
            g_bidCount++;
            Serial.printf("[NET] Bid received from %s (%d total)\n", senderIp, g_bidCount);
        }
    } else {
        Serial.printf("[NET] Unknown packet type 0x%02X\n", pktType);
    }
}

// ============================================================
//  net_selectQuorumAndNotify
//  Called by main.cpp after BID_COLLECTION_MS expires.
//
//  Quorum selection: ideally ranked by staked FLOW balance from
//  the Flow contract REST API. Querying Flow from C++ over HTTPS
//  requires TLS — non-trivial on Pico. For the hackathon we
//  select by arrival order (first MAX_QUORUM_SIZE valid bids).
//  Replace the selection loop with a Flow HTTP query for Phase 2.
// ============================================================
void net_selectQuorumAndNotify() {
    int toSelect = g_bidCount < MAX_QUORUM_SIZE ? g_bidCount : MAX_QUORUM_SIZE;
    g_quorumSize = 0;

    for (int i = 0; i < toSelect; i++) {
        AuditorRecord* rec = findInRegistry(g_bidPool[i].publicKey);
        if (!rec) continue;

        rec->inQuorum = true;
        rec->served   = false;
        g_quorumSize++;

        // ---- Send PKT_QUORUM to this auditor ----
        // Packet: [0x04 | auditor_pubkey | sig_by_transporter]
        // Auditor verifies using transporter pubkey (known from anomaly broadcast).
        // Auditor also checks bytes 1-64 == own pubkey so they know it's addressed to them.
        uint8_t pkt[PKT_SIGNED_SIZE];
        memset(pkt, 0, sizeof(pkt));
        pkt[0] = PKT_QUORUM;
        memcpy(&pkt[1], rec->publicKey, PUBKEY_SIZE);

        uint8_t sig[SIG_SIZE];
        if (!signPayload(pkt, PKT_HEADER_SIZE, sig)) {
            Serial.println("[NET] ERROR: Failed to sign quorum notification.");
            continue;
        }
        memcpy(&pkt[PKT_HEADER_SIZE], sig, SIG_SIZE);

        IPAddress dest;
        dest.fromString(rec->ipAddress);
        udpSocket.beginPacket(dest, rec->port);
        udpSocket.write(pkt, sizeof(pkt));
        udpSocket.endPacket();

        char hex[17]; bytesToHex(rec->publicKey, 8, hex); hex[16] = '\0';
        Serial.printf("[NET] Quorum notification → %s (%s...)\n", rec->ipAddress, hex);
    }

    Serial.printf("[NET] Quorum selected: %d auditors\n", g_quorumSize);
}

// ============================================================
//  net_handleHttp
//  Routes:
//    GET  /data  → quorum check → 402 + nonce
//    POST /pay   → verify sig → serve { csv, payload }
// ============================================================
void net_handleHttp() {
    WiFiClient client = httpServer.available();
    if (!client) return;

    String requestLine = client.readStringUntil('\n');
    requestLine.trim();

    String body        = "";
    int    contentLength = 0;

    while (client.available()) {
        String line = client.readStringUntil('\n');
        line.trim();
        if (line.startsWith("Content-Length:"))
            contentLength = line.substring(15).toInt();
        if (line.length() == 0) break;
    }
    if (contentLength > 0) {
        uint32_t deadline = millis() + 2000;
        while (client.available() < contentLength && millis() < deadline) delay(1);
        for (int i = 0; i < contentLength && client.available(); i++)
            body += (char)client.read();
    }

    Serial.printf("[NET] HTTP: %s\n", requestLine.c_str());

    // ---- GET /data → 402 ----
    if (requestLine.startsWith("GET /data")) {
        // Identify requesting auditor by IP
        char clientIp[16];
        client.remoteIP().toString().toCharArray(clientIp, sizeof(clientIp));
        int regIdx = registryIndexForIp(clientIp);

        if (regIdx < 0) {
            client.println("HTTP/1.1 403 Forbidden");
            client.println("Connection: close\r\n");
            client.println("{\"error\":\"Not in quorum\"}");
            Serial.printf("[NET] 403 — %s not in quorum\n", clientIp);
        } else {
            // Generate a fresh nonce for this auditor's slot
            for (int i = 0; i < 16; i++)
                invoiceNonces[regIdx][i] = (uint8_t)(get_rand_32() & 0xFF);
            noncePending[regIdx] = true;

            char nonceHex[33];
            bytesToHex(invoiceNonces[regIdx], 16, nonceHex);

            char invoiceJson[256];
            snprintf(invoiceJson, sizeof(invoiceJson),
                "{\"status\":\"payment_required\","
                "\"endpoint\":\"/pay\","
                "\"nonce\":\"%s\"}",
                nonceHex);

            client.println("HTTP/1.1 402 Payment Required");
            client.println("Content-Type: application/json");
            client.printf("Content-Length: %d\r\n", strlen(invoiceJson));
            client.println("Connection: close\r\n");
            client.println(invoiceJson);
            Serial.printf("[NET] 402 issued to %s\n", clientIp);
        }

    // ---- POST /pay → verify → serve {csv, payload} ----
    } else if (requestLine.startsWith("POST /pay")) {
        char clientIp[16];
        client.remoteIP().toString().toCharArray(clientIp, sizeof(clientIp));
        int regIdx = registryIndexForIp(clientIp);

        if (regIdx < 0 || !noncePending[regIdx]) {
            client.println("HTTP/1.1 400 Bad Request");
            client.println("Connection: close\r\n");
            client.println("{\"error\":\"No pending invoice for this client\"}");
        } else {
            uint8_t clientPubKey[PUBKEY_SIZE];
            uint8_t clientSig[SIG_SIZE];
            bool    paymentValid = false;

            int pkStart  = body.indexOf("\"pubkey\":\"") + 10;
            int pkEnd    = body.indexOf("\"", pkStart);
            int sigStart = body.indexOf("\"signature\":\"") + 13;
            int sigEnd   = body.indexOf("\"", sigStart);

            if (pkStart > 10 && sigStart > 13 && pkEnd > pkStart && sigEnd > sigStart) {
                size_t pkLen = 0, sigLen = 0;
                bool pkOk  = hexToBytes(body.substring(pkStart,  pkEnd).c_str(),  clientPubKey, &pkLen);
                bool sigOk = hexToBytes(body.substring(sigStart, sigEnd).c_str(), clientSig,    &sigLen);

                if (pkOk && sigOk && pkLen == PUBKEY_SIZE && sigLen == SIG_SIZE) {
                    // Verify auditor signed this event's nonce
                    paymentValid = verifySignature(invoiceNonces[regIdx], 16,
                                                   clientSig, clientPubKey);
                    // Also confirm the pubkey matches the registered quorum auditor
                    if (paymentValid) {
                        paymentValid = (memcmp(clientPubKey,
                                               g_auditorRegistry[regIdx].publicKey,
                                               PUBKEY_SIZE) == 0);
                        if (!paymentValid)
                            Serial.println("[NET] Pubkey mismatch on /pay — rejected.");
                    }
                }
            }

            if (paymentValid) {
                // Build signed payload for this specific auditor
                static char payloadJson[PAYLOAD_MAX_SIZE];
                size_t payloadLen = payload_build(
                    g_auditorRegistry[regIdx].publicKey,
                    payloadJson, sizeof(payloadJson));

                // Build CSV
                static char csvBuf[8192];
                size_t csvLen = imu_buildCsvBuffer(csvBuf, sizeof(csvBuf));

                // Combine into a single JSON response
                // { "csv": "...", "payload": { ... } }
                // We build it in two parts to avoid a huge stack buffer.
                String response = "{\"csv\":\"";
                // Escape newlines in CSV for JSON embedding
                for (size_t i = 0; i < csvLen; i++) {
                    if (csvBuf[i] == '\n')      response += "\\n";
                    else if (csvBuf[i] == '"')  response += "\\\"";
                    else                         response += csvBuf[i];
                }
                response += "\",\"payload\":";
                response += payloadLen > 0 ? payloadJson : "{}";
                response += "}";

                client.println("HTTP/1.1 200 OK");
                client.println("Content-Type: application/json");
                client.printf("Content-Length: %d\r\n", response.length());
                client.println("Connection: close\r\n");
                client.print(response);

                noncePending[regIdx] = false;
                g_auditorRegistry[regIdx].served = true;
                g_servedCount++;
                Serial.printf("[NET] Served to %s (%d/%d quorum done)\n",
                              clientIp, g_servedCount, g_quorumSize);
            } else {
                client.println("HTTP/1.1 403 Forbidden");
                client.println("Connection: close\r\n");
                client.println("{\"error\":\"Invalid signature\"}");
                Serial.printf("[NET] Payment rejected from %s\n", clientIp);
            }
        }

    } else {
        client.println("HTTP/1.1 404 Not Found");
        client.println("Connection: close\r\n");
    }

    client.stop();
}

// ============================================================
//  net_broadcastAnomaly
// ============================================================
void net_broadcastAnomaly(float confidence) {
    uint8_t pkt[PKT_ANOMALY_SIZE];
    memset(pkt, 0, sizeof(pkt));

    pkt[0] = PKT_ANOMALY;
    memcpy(&pkt[1], g_publicKey, PUBKEY_SIZE);
    memcpy(&pkt[PKT_HEADER_SIZE], &confidence, 4);  // float32 LE

    size_t  signedLen = PKT_HEADER_SIZE + 4;
    uint8_t sig[SIG_SIZE];
    if (!signPayload(pkt, signedLen, sig)) {
        Serial.println("[NET] ERROR: Failed to sign anomaly packet.");
        return;
    }
    memcpy(&pkt[signedLen], sig, SIG_SIZE);

    IPAddress multicastGroup;
    multicastGroup.fromString(MULTICAST_IP);
    udpSocket.beginPacket(multicastGroup, MULTICAST_PORT);
    udpSocket.write(pkt, sizeof(pkt));
    udpSocket.endPacket();

    Serial.printf("[NET] Anomaly broadcast. Confidence: %.3f\n", confidence);
}

// ============================================================
//  net_allQuorumServed
// ============================================================
bool net_allQuorumServed() {
    return (g_quorumSize > 0) && (g_servedCount >= g_quorumSize);
}

// ============================================================
//  net_resetEvent
// ============================================================
void net_resetEvent() {
    for (int i = 0; i < MAX_AUDITORS; i++) {
        g_auditorRegistry[i].inQuorum = false;
        g_auditorRegistry[i].served   = false;
        noncePending[i]               = false;
    }
    memset(g_bidPool, 0, sizeof(g_bidPool));
    g_bidCount    = 0;
    g_quorumSize  = 0;
    g_servedCount = 0;
}

// ============================================================
//  net_getLocalIp
// ============================================================
const char* net_getLocalIp() {
    static char ipBuf[16];
    WiFi.localIP().toString().toCharArray(ipBuf, sizeof(ipBuf));
    return ipBuf;
}
