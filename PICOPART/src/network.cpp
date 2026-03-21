#include "network.h"
#include "crypto.h"
#include "config.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>
#include <Arduino.h>
#include <string.h>
#include <pico/rand.h>

// ── External state injected by main.cpp ──────────────────────────────────────
extern uint8_t  g_privKey[PRIVKEY_BYTES];
extern uint8_t  g_pubKey[PUBKEY_BYTES];
extern char     g_pubHex[PUBKEY_HEX_LEN + 1];
extern float    g_lastConfidence;
extern char     g_currentEventId[256];   // submission_sig hex

// ── Module globals ────────────────────────────────────────────────────────────
AuditorEntry g_auditorRegistry[MAX_AUDITORS];
int          g_auditorCount  = 0;
BidEntry     g_bidPool[MAX_AUDITORS];
int          g_bidCount      = 0;
QuorumEntry  g_quorum[MAX_QUORUM];
int          g_quorumSize    = 0;
NonceEntry   g_nonces[MAX_QUORUM];
bool         g_collectingBids = false;
char         g_csvBuffer[8192];

// ── UDP sockets ──────────────────────────────────────────────────────────────
static WiFiUDP _mcastSock;   // port 5005 — beacons in, anomaly out
static WiFiUDP _bidSock;     // port 5006 — bids in (unicast)

// ── HTTP server ───────────────────────────────────────────────────────────────
static WiFiServer _httpServer(HTTP_PORT);

// ── Payload signatures issued per auditor: pubkey_hex → sig_hex ──────────────
static char  _issuedPayloadSigs[MAX_QUORUM][PUBKEY_HEX_LEN + 1];  // key
static char  _issuedPayloadSigVal[MAX_QUORUM][SIG_BYTES * 2 + 1]; // value
static int   _issuedCount = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────
static void _fresh_nonce(uint8_t *out) {
    for (int i = 0; i < NONCE_BYTES; i += 4) {
        uint32_t r = get_rand_32();
        memcpy(out + i, &r, (NONCE_BYTES - i) >= 4 ? 4 : NONCE_BYTES - i);
    }
}

static NonceEntry *_find_nonce(const char *pub_hex) {
    for (int i = 0; i < MAX_QUORUM; i++)
        if (g_nonces[i].valid && strcmp(g_nonces[i].pubkey_hex, pub_hex) == 0)
            return &g_nonces[i];
    return nullptr;
}

static NonceEntry *_alloc_nonce(const char *pub_hex) {
    for (int i = 0; i < MAX_QUORUM; i++) {
        if (!g_nonces[i].valid) {
            strlcpy(g_nonces[i].pubkey_hex, pub_hex, sizeof(g_nonces[i].pubkey_hex));
            g_nonces[i].valid = true;
            return &g_nonces[i];
        }
    }
    return nullptr;  // all slots occupied
}

static bool _pubhex_in_quorum(const char *pub_hex) {
    for (int i = 0; i < g_quorumSize; i++)
        if (strcmp(g_quorum[i].pubkey_hex, pub_hex) == 0) return true;
    return false;
}

static bool _pubhex_in_registry(const char *pub_hex) {
    for (int i = 0; i < g_auditorCount; i++)
        if (strcmp(g_auditorRegistry[i].pubkey_hex, pub_hex) == 0) return true;
    return false;
}

// Find or create registry entry; return index or -1 if full
static int _registry_upsert(const uint8_t *pub, const char *pub_hex, const char *ip) {
    for (int i = 0; i < g_auditorCount; i++) {
        if (strcmp(g_auditorRegistry[i].pubkey_hex, pub_hex) == 0) {
            strlcpy(g_auditorRegistry[i].ip, ip, sizeof(g_auditorRegistry[i].ip));
            g_auditorRegistry[i].last_seen_ms = millis();
            return i;
        }
    }
    if (g_auditorCount >= MAX_AUDITORS) return -1;
    int i = g_auditorCount++;
    memcpy(g_auditorRegistry[i].pubkey, pub, PUBKEY_BYTES);
    strlcpy(g_auditorRegistry[i].pubkey_hex, pub_hex, sizeof(g_auditorRegistry[i].pubkey_hex));
    strlcpy(g_auditorRegistry[i].ip, ip, sizeof(g_auditorRegistry[i].ip));
    g_auditorRegistry[i].last_seen_ms = millis();
    g_auditorRegistry[i].active = true;
    return i;
}

// ── PKT_BEACON handler (0x01, 129 bytes) ──────────────────────────────────────
static void _handle_beacon(const uint8_t *pkt, const char *src_ip) {
    const uint8_t *pub = pkt + 1;        // 64 bytes
    const uint8_t *sig = pkt + 65;       // 64 bytes
    // Sybil gate: verify sig over bytes 0-64
    if (!crypto_verify(pub, pkt, 65, sig)) {
        Serial.printf("[UDP] Beacon from %s — bad sig, dropped\n", src_ip);
        return;
    }
    char pub_hex[PUBKEY_HEX_LEN + 1];
    bytes_to_hex(pub, PUBKEY_BYTES, pub_hex);
    int idx = _registry_upsert(pub, pub_hex, src_ip);
    if (idx < 0) {
        Serial.println("[UDP] Registry full — beacon ignored");
        return;
    }
    Serial.printf("[UDP] Beacon OK  %s  pub=%s...\n", src_ip, pub_hex + (PUBKEY_HEX_LEN - 12));
}

// ── PKT_BID handler (0x02, 137 bytes) ────────────────────────────────────────
static void _handle_bid(const uint8_t *pkt, const char *src_ip) {
    Serial.printf("[UDP] _handle_bid called from %s collecting=%d\n", 
                  src_ip, g_collectingBids);  // add this
    
    if (!g_collectingBids) {
        Serial.println("[UDP] Bid dropped — not collecting");  // add this
        return;
    }

    const uint8_t *pub        = pkt + 1;   // 64 bytes
    const uint8_t *price_bytes = pkt + 65; // 8 bytes float64 LE
    const uint8_t *sig        = pkt + 73;  // 64 bytes, covers bytes 0-72

    // Sybil gate: verify sig over bytes 0-72
    if (!crypto_verify(pub, pkt, 73, sig)) {
        Serial.printf("[UDP] Bid from %s — bad sig, dropped\n", src_ip);
        return;
    }

    char pub_hex[PUBKEY_HEX_LEN + 1];
    bytes_to_hex(pub, PUBKEY_BYTES, pub_hex);
    Serial.printf("[UDP] Bid sig OK from %s pub=...%s\n", 
                  src_ip, pub_hex + PUBKEY_HEX_LEN - 12);  // add this

    // Must have registered via beacon first
    if (!_pubhex_in_registry(pub_hex)) {
        Serial.printf("[UDP] Registry has %d entries\n", g_auditorCount);  // add this
        return;
    }

    // Deduplicate per auditor
    for (int i = 0; i < g_bidCount; i++){
        if (strcmp(g_bidPool[i].pubkey_hex, pub_hex) == 0){
            Serial.println("[UDP] Duplicate bid — dropped");
            return;
        } 
    }    
    if (g_bidCount >= MAX_AUDITORS) {
        Serial.println("[UDP] Bid pool full");  // add this
        return;
    }

    double price;
    memcpy(&price, price_bytes, 8);   // little-endian float64

    BidEntry &b = g_bidPool[g_bidCount++];
    strlcpy(b.pubkey_hex, pub_hex, sizeof(b.pubkey_hex));
    strlcpy(b.ip, src_ip, sizeof(b.ip));
    b.price = price;
    b.rep   = 0.0f;
    b.stake = 0.0f;
    b.score = 0.0f;

    Serial.printf("[UDP] Bid OK  %s  price=%.4f FLOW  bidCount=%d\n", 
                  src_ip, price, g_bidCount);
}

// ── UDP poll ──────────────────────────────────────────────────────────────────
void net_handleUdp() {
    // ── Multicast socket (port 5005) — beacons only
    int sz = _mcastSock.parsePacket();
    if (sz > 0) {
        uint8_t pkt[256];
        int n = _mcastSock.read(pkt, sizeof(pkt));
        char src[20];
        _mcastSock.remoteIP().toString().toCharArray(src, sizeof(src));

        if (n == 129 && pkt[0] == 0x01) _handle_beacon(pkt, src);
        // 0x02/0x03/0x04 on the multicast socket are ignored
    }

    // ── Unicast bid socket (port 5006)
    sz = _bidSock.parsePacket();
    if (sz > 0) {
        Serial.printf("[UDP] Bid socket got %d bytes\n", sz);
        uint8_t pkt[256];
        int n = _bidSock.read(pkt, sizeof(pkt));
        char src[20];
        _bidSock.remoteIP().toString().toCharArray(src, sizeof(src));

        Serial.printf("[UDP] Bid packet: n=%d type=0x%02x from=%s\n", 
                  n, pkt[0], src);  // add this

        if (n == 137 && pkt[0] == 0x02) _handle_bid(pkt, src);
        else Serial.printf("[UDP] Bid ignored: wrong size or type\n");  // add this
        }
    }

// ── PKT_ANOMALY builder and broadcast ─────────────────────────────────────────
// PKT_ANOMALY (133 bytes): [0x03 | pub 64B | conf float32 LE 4B | sig 64B]
void net_sendAnomaly(float confidence) {
    uint8_t pkt[133];
    pkt[0] = 0x03;
    memcpy(pkt + 1, g_pubKey, PUBKEY_BYTES);
    memcpy(pkt + 65, &confidence, 4);   // float32 LE (native on ARM Cortex-M)
    if (!crypto_sign(g_privKey, pkt, 69, pkt + 69)) {
        Serial.println("[Net] Anomaly sig failed");
        return;
    }
    _mcastSock.beginPacketMulticast(IPAddress(239, 0, 0, 1), MULTICAST_PORT, WiFi.localIP());
    _mcastSock.write(pkt, 133);
    _mcastSock.endPacket();
    Serial.printf("[Net] PKT_ANOMALY sent  conf=%.4f\n", confidence);
}

// ── PKT_QUORUM builder and unicast ────────────────────────────────────────────
// PKT_QUORUM (129 bytes): [0x04 | nominated_pubkey 64B | sig_by_transporter 64B]
void net_sendQuorumNotify(const QuorumEntry *entry) {
    uint8_t pkt[129];
    pkt[0] = 0x04;
    memcpy(pkt + 1, entry->pubkey, PUBKEY_BYTES);
    if (!crypto_sign(g_privKey, pkt, 65, pkt + 65)) {
        Serial.println("[Net] Quorum sig failed");
        return;
    }
    IPAddress dst;
    dst.fromString(entry->ip);
    _mcastSock.beginPacket(dst, MULTICAST_PORT);
    _mcastSock.write(pkt, 129);
    _mcastSock.endPacket();
    Serial.printf("[Net] PKT_QUORUM → %s  pub=...%s\n",
                  entry->ip, entry->pubkey_hex + PUBKEY_HEX_LEN - 12);
}

// ── Quorum selection ──────────────────────────────────────────────────────────
// score = W_PRICE*(1/price) + W_REP*rep + W_STAKE*stake
// When FLOW_ENABLED=0: rep=0, stake=0 → rank purely by lowest bid price.
int net_selectQuorum(const char */*transporter_pub_hex*/) {
    if (g_bidCount == 0) return 0;

    // Compute scores
    for (int i = 0; i < g_bidCount; i++) {
        BidEntry &b = g_bidPool[i];
        if (b.price <= 0.0) { b.score = -1e9f; continue; }
        b.score = QUORUM_W_PRICE * (1.0f / (float)b.price)
                + QUORUM_W_REP   * b.rep
                + QUORUM_W_STAKE * b.stake;
    }

    // Selection sort descending by score — O(n²) fine for n≤16
    for (int i = 0; i < g_bidCount - 1; i++) {
        int best = i;
        for (int j = i+1; j < g_bidCount; j++)
            if (g_bidPool[j].score > g_bidPool[best].score) best = j;
        if (best != i) { BidEntry tmp = g_bidPool[i]; g_bidPool[i] = g_bidPool[best]; g_bidPool[best] = tmp; }
    }

    g_quorumSize = 0;
    for (int i = 0; i < g_bidCount && g_quorumSize < QUORUM_SIZE; i++) {
        if (g_bidPool[i].score < 0) continue;
        QuorumEntry &q = g_quorum[g_quorumSize++];
        strlcpy(q.pubkey_hex, g_bidPool[i].pubkey_hex, sizeof(q.pubkey_hex));
        strlcpy(q.ip,         g_bidPool[i].ip,         sizeof(q.ip));
        // Recover pubkey bytes from registry
        for (int k = 0; k < g_auditorCount; k++) {
            if (strcmp(g_auditorRegistry[k].pubkey_hex, q.pubkey_hex) == 0) {
                memcpy(q.pubkey, g_auditorRegistry[k].pubkey, PUBKEY_BYTES);
                break;
            }
        }
        Serial.printf("[Quorum] %s  price=%.4f  score=%.4f\n",
                      q.ip, g_bidPool[i].price, g_bidPool[i].score);
    }
    return g_quorumSize;
}

// ── HTTP server ───────────────────────────────────────────────────────────────
// Minimal line-by-line HTTP/1.0 parser for GET /data and POST /pay

static void _http_send(WiFiClient &cli, int code, const char *ctype, const char *body) {
    const char *status = (code == 200) ? "OK" : (code == 402) ? "Payment Required" :
                         (code == 400) ? "Bad Request" : (code == 403) ? "Forbidden" :
                         (code == 404) ? "Not Found" : (code == 409) ? "Conflict" : "Error";
    cli.printf("HTTP/1.0 %d %s\r\n", code, status);
    cli.printf("Content-Type: %s\r\n", ctype);
    cli.printf("Content-Length: %d\r\n", (int)strlen(body));
    cli.printf("Access-Control-Allow-Origin: *\r\n");
    cli.printf("Connection: close\r\n\r\n");
    cli.print(body);
}

static void _handle_GET_data(WiFiClient &cli, const char *query) {
    // Extract pubkey from query string "pubkey=<128hex>"
    const char *pk_start = strstr(query, "pubkey=");
    if (!pk_start) {
        _http_send(cli, 400, "application/json", "{\"error\":\"missing pubkey\"}");
        return;
    }
    pk_start += 7;
    Serial.printf("[HTTP] pubkey_len=%d expected=%d\n", (int)strlen(pk_start), PUBKEY_HEX_LEN);  // add this
    if (strlen(pk_start) < PUBKEY_HEX_LEN) {
        _http_send(cli, 400, "application/json", "{\"error\":\"pubkey too short\"}");
        return;
    }
    char pub_hex[PUBKEY_HEX_LEN + 1];
    memcpy(pub_hex, pk_start, PUBKEY_HEX_LEN);
    pub_hex[PUBKEY_HEX_LEN] = '\0';

    if (g_quorumSize == 0) {
        _http_send(cli, 403, "application/json", "{\"error\":\"no active quorum\"}");
        return;
    }
    if (!_pubhex_in_quorum(pub_hex)) {
        _http_send(cli, 403, "application/json", "{\"error\":\"pubkey not in quorum\"}");
        return;
    }

    // Generate and store nonce
    NonceEntry *ne = _find_nonce(pub_hex);
    if (!ne) ne = _alloc_nonce(pub_hex);
    if (!ne) {
        _http_send(cli, 500, "application/json", "{\"error\":\"nonce table full\"}");
        return;
    }
    _fresh_nonce(ne->nonce);

    char nonce_hex[NONCE_BYTES * 2 + 1];
    bytes_to_hex(ne->nonce, NONCE_BYTES, nonce_hex);

    char body[256];
    snprintf(body, sizeof(body),
        "{\"status\":\"payment_required\","
        "\"endpoint\":\"/pay\","
        "\"nonce\":\"%s\","
        "\"description\":\"Sign the nonce with your private key\"}",
        nonce_hex);
    _http_send(cli, 402, "application/json", body);
}

static void _handle_POST_pay(WiFiClient &cli, const char *json_body) {
    JsonDocument doc;
    if (deserializeJson(doc, json_body) != DeserializationError::Ok) {
        _http_send(cli, 400, "application/json", "{\"error\":\"invalid JSON\"}");
        return;
    }
    const char *pub_hex = doc["pubkey"] | "";
    const char *sig_hex = doc["signature"] | "";

    if (strlen(pub_hex) != PUBKEY_HEX_LEN || strlen(sig_hex) != SIG_BYTES * 2) {
        _http_send(cli, 400, "application/json", "{\"error\":\"bad field lengths\"}");
        return;
    }

    NonceEntry *ne = _find_nonce(pub_hex);
    if (!ne) {
        _http_send(cli, 403, "application/json", "{\"error\":\"no pending nonce\"}");
        return;
    }

    uint8_t pub[PUBKEY_BYTES], sig[SIG_BYTES];
    if (!hex_to_bytes(pub_hex, PUBKEY_HEX_LEN, pub) ||
        !hex_to_bytes(sig_hex, SIG_BYTES * 2, sig)) {
        _http_send(cli, 400, "application/json", "{\"error\":\"hex decode failed\"}");
        return;
    }

    if (!crypto_verify(pub, ne->nonce, NONCE_BYTES, sig)) {
        _http_send(cli, 403, "application/json", "{\"error\":\"signature verification failed\"}");
        return;
    }

    if (!_pubhex_in_quorum(pub_hex)) {
        _http_send(cli, 403, "application/json", "{\"error\":\"not in quorum\"}");
        return;
    }

    // Invalidate nonce (replay prevention)
    ne->valid = false;

    // Build canonical JSON for payload signature
    char canonical[512];
    snprintf(canonical, sizeof(canonical),
        "{\"anomaly_confidence\":%.4f,\"auditor_pubkey\":\"%s\","
        "\"event_id\":\"%s\",\"timestamp_ms\":%lu,\"transporter_pubkey\":\"%s\"}",
        g_lastConfidence, pub_hex, g_currentEventId, (unsigned long)millis(), g_pubHex);

    uint8_t payload_sig[SIG_BYTES];
    crypto_sign(g_privKey, (const uint8_t *)canonical, strlen(canonical), payload_sig);
    char payload_sig_hex[SIG_BYTES * 2 + 1];
    bytes_to_hex(payload_sig, SIG_BYTES, payload_sig_hex);

    // Store issued payload sig
    if (_issuedCount < MAX_QUORUM) {
        strlcpy(_issuedPayloadSigs[_issuedCount], pub_hex, sizeof(_issuedPayloadSigs[0]));
        strlcpy(_issuedPayloadSigVal[_issuedCount], payload_sig_hex, sizeof(_issuedPayloadSigVal[0]));
        _issuedCount++;
    }

    // Build payload JSON
    char payload_json[768];
    snprintf(payload_json, sizeof(payload_json),
        "{\"transporter_pubkey\":\"%s\","
        "\"auditor_pubkey\":\"%s\","
        "\"anomaly_confidence\":%.4f,"
        "\"timestamp_ms\":%lu,"
        "\"event_id\":\"%s\","
        "\"payload_signature\":\"%s\"}",
        g_pubHex, pub_hex, g_lastConfidence,
        (unsigned long)millis(), g_currentEventId, payload_sig_hex);

    // Count escaped CSV length (\n becomes \\n = 2 bytes)
    size_t csv_escaped_len = 0;
    const char *p = g_csvBuffer;
    while (*p) {
        csv_escaped_len += (*p == '\n') ? 2 : 1;
        p++;
    }

    // Total body: {"csv":"<escaped>","payload":<payload_json>}
    // {"csv":"    = 8 chars
    // ","payload": = 12 chars
    // }            = 1 char
    size_t payload_len = strlen(payload_json);
    int total_len = 8 + (int)csv_escaped_len + 12 + (int)payload_len + 1;

    cli.printf("HTTP/1.0 200 OK\r\n");
    cli.printf("Content-Type: application/json\r\n");
    cli.printf("Content-Length: %d\r\n", total_len);
    cli.printf("Access-Control-Allow-Origin: *\r\n");
    cli.printf("Connection: close\r\n\r\n");

    // Stream body in parts to avoid large buffer
    cli.printf("{\"csv\":\"");
    p = g_csvBuffer;
    while (*p) {
        if (*p == '\n') cli.print("\\n");
        else            cli.write(*p);
        p++;
    }
    cli.printf("\",\"payload\":%s}", payload_json);

    Serial.printf("[HTTP] 200 /pay  pub=...%s\n", pub_hex + PUBKEY_HEX_LEN - 12);
}

static void _handle_POST_verdict(WiFiClient &cli, const char *json_body) {
    // In FLOW_ENABLED=0 mode, /verdict is a no-op on the Pico.
    // Verdicts go directly to mock_transporter.py or the Flow contract.
    // This endpoint exists only so auditors have somewhere to POST during testing
    // when they mistakenly point at the Pico instead of the mock.
    (void)json_body;
    _http_send(cli, 200, "application/json", "{\"status\":\"received\"}");
}

void net_handleHttp() {
    WiFiClient cli = _httpServer.accept();
    if (!cli) return;

    uint32_t deadline = millis() + 1000;
    while (!cli.available() && millis() < deadline) delay(1);
    if (!cli.available()) { cli.stop(); return; }

    // Read request line
    String req_line = cli.readStringUntil('\n');
    req_line.trim();

    // Read headers (discard all except Content-Length)
    int content_length = 0;
    while (cli.available()) {
        String hdr = cli.readStringUntil('\n');
        hdr.trim();
        if (hdr.length() == 0) break;   // blank line = end of headers
        if (hdr.startsWith("Content-Length:") || hdr.startsWith("content-length:")) {
            content_length = hdr.substring(hdr.indexOf(':') + 1).toInt();
        }
    }

    // Parse method and path
    char method[8], path[256], query[256];
    query[0] = '\0';
    sscanf(req_line.c_str(), "%7s %255s", method, path);
    Serial.printf("[HTTP] method=%s path=%s\n", method, path);  // add this
    Serial.printf("[HTTP] query=%s len=%d\n", query, (int)strlen(query));  // add this

    // Split path?query
    char *qmark = strchr(path, '?');
    if (qmark) {
        strlcpy(query, qmark + 1, sizeof(query));
        *qmark = '\0';
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/data") == 0) {
        _handle_GET_data(cli, query);

    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/pay") == 0) {
        char body[512] = {};
        if (content_length > 0 && content_length < (int)sizeof(body)) {
            int n = cli.readBytes(body, content_length);
            body[n] = '\0';
        }
        _handle_POST_pay(cli, body);

    } else if (strcmp(method, "POST") == 0 && strcmp(path, "/verdict") == 0) {
        char body[1024] = {};
        if (content_length > 0 && content_length < (int)sizeof(body)) {
            int n = cli.readBytes(body, content_length);
            body[n] = '\0';
        }
        _handle_POST_verdict(cli, body);

    } else if (strcmp(method, "OPTIONS") == 0) {
        _http_send(cli, 204, "text/plain", "");

    } else {
        _http_send(cli, 404, "application/json", "{\"error\":\"not found\"}");
    }

    cli.flush();
    cli.stop();
}

// ── Init ──────────────────────────────────────────────────────────────────────
bool net_init() {
    // Multicast listener (beacons and anomaly broadcasts)
    if (!_mcastSock.beginMulticast(IPAddress(239, 0, 0, 1), MULTICAST_PORT)) {
        Serial.println("[Net] Multicast join failed");
        return false;
    }
    // Unicast bid listener
    if (!_bidSock.begin(BID_PORT)) {
        Serial.println("[Net] Bid socket bind failed");
        return false;
    }
    _httpServer.begin();
    Serial.printf("[Net] Multicast joined 239.0.0.1:%d\n", MULTICAST_PORT);
    Serial.printf("[Net] Bid listener on :%d\n", BID_PORT);
    Serial.printf("[Net] HTTP server on :%d\n", HTTP_PORT);
    return true;
}