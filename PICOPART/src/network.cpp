#include "network.h"
#include "imu.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <string.h>
#include <stdio.h>

#define PKT_BEACON   0x01
#define PKT_BID      0x02
#define PKT_ANOMALY  0x03

#define PKT_HEADER_SIZE  (1 + PUBKEY_SIZE)           // type + pubkey = 65 bytes
#define PKT_SIGNED_SIZE  (PKT_HEADER_SIZE + SIG_SIZE) // 65 + 64 = 129 bytes
#define PKT_ANOMALY_SIZE (PKT_HEADER_SIZE + 4 + SIG_SIZE) // 133 bytes

static WiFiUDP  udpSocket;
static WiFiServer httpServer(HTTP_PORT);

AuditorRecord g_auditorRegistry[MAX_AUDITORS] = {};
int           g_auditorCount = 0;

uint8_t g_winningAuditorPubKey[PUBKEY_SIZE] = {};
bool    g_hasWinner = false;

static uint8_t pendingInvoiceNonce[16] = {};
static bool    hasPendingInvoice = false;

static uint8_t udpBuf[256];

bool net_init() {
    // ---- Connect to Wi-Fi ----
    Serial.print("[NET] Connecting to Wi-Fi");
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
        if (millis() - start > 20000) {
            Serial.println("\n[NET] ERROR: Wi-Fi connection timed out.");
            return false;
        }
    }
    Serial.print("\n[NET] Connected. IP: ");
    Serial.println(WiFi.localIP());

    // ---- Join UDP multicast group ----
    // beginMulticast(localIP, groupIP, port) tells the lwip stack to
    // subscribe to the multicast group so we receive those datagrams.
    IPAddress multicastGroup;
    multicastGroup.fromString(MULTICAST_IP);
    udpSocket.beginMulticast(WiFi.localIP(), multicastGroup, MULTICAST_PORT);
    Serial.print("[NET] Listening on UDP multicast ");
    Serial.print(MULTICAST_IP);
    Serial.print(":");
    Serial.println(MULTICAST_PORT);

    // ---- Start HTTP server ----
    httpServer.begin();
    Serial.print("[NET] x402 HTTP server on port ");
    Serial.println(HTTP_PORT);

    return true;
}

static AuditorRecord* findOrAddAuditor(const uint8_t pubKey[PUBKEY_SIZE],
                                        const char* ip, uint16_t port) {
    // Look for an existing entry with this key.
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (g_auditorRegistry[i].active &&
            memcmp(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE) == 0) {
            return &g_auditorRegistry[i];
        }
    }
    // Find an empty slot.
    for (int i = 0; i < MAX_AUDITORS; i++) {
        if (!g_auditorRegistry[i].active) {
            memcpy(g_auditorRegistry[i].publicKey, pubKey, PUBKEY_SIZE);
            strncpy(g_auditorRegistry[i].ipAddress, ip, 15);
            g_auditorRegistry[i].port   = port;
            g_auditorRegistry[i].active = true;
            g_auditorCount++;

            char hex[PUBKEY_SIZE * 2 + 1];
            bytesToHex(pubKey, 8, hex);  // just print first 8 bytes for readability
            hex[16] = '\0';
            Serial.print("[NET] New auditor registered: ");
            Serial.print(hex);
            Serial.print("... from ");
            Serial.println(ip);

            return &g_auditorRegistry[i];
        }
    }
    Serial.println("[NET] WARNING: Auditor registry full.");
    return nullptr;
}

void net_handleUdp() {
    int packetSize = udpSocket.parsePacket();
    if (packetSize <= 0) return;

    // Guard against oversized packets.
    if (packetSize > (int)sizeof(udpBuf)) {
        Serial.println("[NET] Oversized UDP packet — dropped.");
        return;
    }

    int bytesRead = udpSocket.read(udpBuf, sizeof(udpBuf));
    if (bytesRead < (int)PKT_SIGNED_SIZE) {
        Serial.println("[NET] Undersized UDP packet — dropped.");
        return;
    }

    uint8_t pktType = udpBuf[0];
    const uint8_t* senderPubKey = &udpBuf[1];          // 64 bytes
    const uint8_t* signature    = &udpBuf[PKT_HEADER_SIZE]; // 64 bytes

    // ---- SYBIL GATE: verify signature before touching any state ----
    // The signed region is everything before the signature itself.
    bool valid = verifySignature(udpBuf, PKT_HEADER_SIZE,
                                 signature, senderPubKey);
    if (!valid) {
        // Rejected. Log it with the sender IP for the dashboard.
        Serial.print("[NET] REJECTED unsigned/invalid packet from ");
        Serial.println(udpSocket.remoteIP().toString());
        return;
    }

    // ---- Signature verified — safe to process ----
    char senderIp[16];
    udpSocket.remoteIP().toString().toCharArray(senderIp, sizeof(senderIp));
    uint16_t senderPort = udpSocket.remotePort();

    if (pktType == PKT_BEACON) {
        // Refresh or create the registry entry for this Auditor.
        AuditorRecord* rec = findOrAddAuditor(senderPubKey, senderIp, senderPort);
        if (rec) rec->lastSeenMs = millis();

    } else if (pktType == PKT_BID) {
        // An Auditor is bidding for the anomaly data.
        // For the prototype, the first valid bid wins.
        if (!g_hasWinner) {
            memcpy(g_winningAuditorPubKey, senderPubKey, PUBKEY_SIZE);
            g_hasWinner = true;

            char hex[17];
            bytesToHex(senderPubKey, 8, hex);
            hex[16] = '\0';
            Serial.print("[NET] Winning bid from auditor: ");
            Serial.println(hex);
        }
    } else {
        Serial.print("[NET] Unknown packet type: 0x");
        Serial.println(pktType, HEX);
    }
}

void net_handleHttp() {
    WiFiClient client = httpServer.available();
    if (!client) return;

    // Read the request line (first line of HTTP request).
    // We only need the method and path — headers are ignored
    // for this prototype. A real implementation would validate
    // the Host header and Content-Type at minimum.
    String requestLine = client.readStringUntil('\n');
    requestLine.trim();

    // Drain remaining headers so the client doesn't stall.
    String body = "";
    bool inBody = false;
    int contentLength = 0;

    while (client.available()) {
        String line = client.readStringUntil('\n');
        line.trim();
        if (line.startsWith("Content-Length:")) {
            contentLength = line.substring(15).toInt();
        }
        if (line.length() == 0) {
            inBody = true;
            break;
        }
    }
    if (inBody && contentLength > 0) {
        // Read the POST body (contains the signed invoice).
        uint32_t deadline = millis() + 2000;
        while (client.available() < contentLength && millis() < deadline) {
            delay(1);
        }
        for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
        }
    }

    Serial.print("[NET] HTTP request: ");
    Serial.println(requestLine);

    // ---- Route: GET /data → 402 Payment Required ----
    if (requestLine.startsWith("GET /data")) {
        // Generate a fresh nonce for this invoice.
        // The Auditor must sign {nonce + their_public_key} and
        // submit it to /pay. This prevents replay attacks.
        for (int i = 0; i < 16; i++) {
            // RP2350 hardware TRNG — much stronger than the RP2040's ROSC approach.
        pendingInvoiceNonce[i] = (uint8_t)(get_rand_32() & 0xFF);
        }
        hasPendingInvoice = true;

        char nonceHex[33];
        bytesToHex(pendingInvoiceNonce, 16, nonceHex);

        // Build the JSON invoice body.
        char invoiceJson[256];
        snprintf(invoiceJson, sizeof(invoiceJson),
            "{\"status\":\"payment_required\","
            "\"endpoint\":\"/pay\","
            "\"nonce\":\"%s\","
            "\"description\":\"Sign this nonce with your ECDSA private key\"}",
            nonceHex);

        client.println("HTTP/1.1 402 Payment Required");
        client.println("Content-Type: application/json");
        client.print("Content-Length: ");
        client.println(strlen(invoiceJson));
        client.println("Connection: close");
        client.println();
        client.println(invoiceJson);

        Serial.println("[NET] Issued 402 invoice.");

    // ---- Route: POST /pay → verify signature, return CSV ----
    } else if (requestLine.startsWith("POST /pay")) {
        if (!hasPendingInvoice) {
            client.println("HTTP/1.1 400 Bad Request");
            client.println("Connection: close");
            client.println();
            client.println("{\"error\":\"No pending invoice\"}");
        } else {
            // Expected body: JSON with "pubkey" and "signature" hex strings.
            // {"pubkey":"<128 hex chars>","signature":"<128 hex chars>"}
            // Parse crudely — for production use ArduinoJson here.
            // For the prototype this works because the format is fixed.

            bool paymentValid = false;
            uint8_t clientPubKey[PUBKEY_SIZE];
            uint8_t clientSig[SIG_SIZE];

            // Extract pubkey field
            int pkStart = body.indexOf("\"pubkey\":\"") + 10;
            int pkEnd   = body.indexOf("\"", pkStart);
            // Extract signature field
            int sigStart = body.indexOf("\"signature\":\"") + 13;
            int sigEnd   = body.indexOf("\"", sigStart);

            if (pkStart > 10 && sigStart > 13 && pkEnd > pkStart && sigEnd > sigStart) {
                String pkHex  = body.substring(pkStart, pkEnd);
                String sigHex = body.substring(sigStart, sigEnd);

                size_t pkLen, sigLen;
                bool pkOk  = hexToBytes(pkHex.c_str(),  clientPubKey, &pkLen);
                bool sigOk = hexToBytes(sigHex.c_str(), clientSig,    &sigLen);

                if (pkOk && sigOk && pkLen == PUBKEY_SIZE && sigLen == SIG_SIZE) {
                    // Verify: the client signed pendingInvoiceNonce with their private key.
                    paymentValid = verifySignature(pendingInvoiceNonce, 16,
                                                   clientSig, clientPubKey);
                    if (paymentValid) {
                        // Record the winner for the JSON payload.
                        memcpy(g_winningAuditorPubKey, clientPubKey, PUBKEY_SIZE);
                        g_hasWinner = true;
                    }
                }
            }

            if (paymentValid) {
                // Build and serve the CSV buffer.
                static char CSVBuf[8192];
                size_t CSVLen = imu_buildCSVBuffer(CSVBuf, sizeof(CSVBuf));

                client.println("HTTP/1.1 200 OK");
                client.println("Content-Type: text/CSV");
                client.print("Content-Length: ");
                client.println(CSVLen);
                client.println("Connection: close");
                client.println();
                client.print(CSVBuf);

                hasPendingInvoice = false;
                Serial.println("[NET] Payment verified — CSV served.");
            } else {
                client.println("HTTP/1.1 403 Forbidden");
                client.println("Connection: close");
                client.println();
                client.println("{\"error\":\"Invalid signature\"}");
                Serial.println("[NET] Payment rejected — bad signature.");
            }
        }

    // ---- Unknown route ----
    } else {
        client.println("HTTP/1.1 404 Not Found");
        client.println("Connection: close");
        client.println();
    }

    client.stop();
}

void net_broadcastAnomaly(float confidence) {
    uint8_t pkt[PKT_ANOMALY_SIZE];
    memset(pkt, 0, sizeof(pkt));

    // Build the unsigned portion of the anomaly packet.
    pkt[0] = PKT_ANOMALY;
    memcpy(&pkt[1], g_publicKey, PUBKEY_SIZE);

    // Encode the float confidence score as 4 little-endian bytes.
    // We use memcpy here (not a cast) to avoid strict aliasing UB.
    memcpy(&pkt[PKT_HEADER_SIZE], &confidence, 4);

    // Sign the packet header + confidence (everything before the sig).
    size_t signedLen = PKT_HEADER_SIZE + 4;
    uint8_t sig[SIG_SIZE];
    if (!signPayload(pkt, signedLen, sig)) {
        Serial.println("[NET] ERROR: Failed to sign anomaly packet.");
        return;
    }
    memcpy(&pkt[signedLen], sig, SIG_SIZE);

    // Broadcast to the multicast group.
    IPAddress multicastGroup;
    multicastGroup.fromString(MULTICAST_IP);
    udpSocket.beginPacket(multicastGroup, MULTICAST_PORT);
    udpSocket.write(pkt, sizeof(pkt));
    udpSocket.endPacket();

    Serial.print("[NET] Anomaly broadcast sent. Confidence: ");
    Serial.println(confidence, 3);
}

const char* net_getLocalIp() {
    static char ipBuf[16];
    WiFi.localIP().toString().toCharArray(ipBuf, sizeof(ipBuf));
    return ipBuf;
}