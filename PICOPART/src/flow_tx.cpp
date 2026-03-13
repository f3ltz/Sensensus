// flow_tx.cpp — on-device Flow transaction construction for the Pico 2W (RP2350)
// Architecture: PL_Genesis Hackathon 2026
//
// Self-contained: SHA3-256 (SW), RLP encoder, Base64, HTTPS GET/POST, and the
// complete Flow transaction envelope construction, signing, and submission.
//
// Why this works without a relay:
//   crypto.cpp already calls uECC_sign(priv, hash32, 32, sig, secp256r1()).
//   uECC_sign operates on a *pre-hashed* 32-byte message. Flow just requires
//   SHA3-256 of the envelope rather than SHA-256. Same key, same curve,
//   different hash — no firmware restructure needed.
//
// Memory budget (RP2350, 520 KB SRAM):
//   SHA3 state      : 200 B
//   RLP staging     : 8 KB  (static, not on stack)
//   TX body JSON    : 8 KB  (static)
//   Response buffers: 2 KB  (static)
//   Total           : ~19 KB — well within budget alongside TFLite (~64 KB)

#include "flow_tx.h"
#include "config.h"
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <Arduino.h>
#include <uECC.h>
#include <string.h>
#include <stdio.h>

// ── Module state ──────────────────────────────────────────────────────────────
static uint8_t _priv[32];
static char    _account_addr[24];   // "0x<16 hex>"
static uint8_t _account_raw[8];     // 8-byte raw Flow address for RLP
static char    _contract_addr[24];
static char    _api_host[64];       // "rest-testnet.onflow.org"

// ═════════════════════════════════════════════════════════════════════════════
// §1  SHA3-256 — Keccak-f[1600], NIST padding 0x06
// ═════════════════════════════════════════════════════════════════════════════
#define SHA3_RATE 136   // (1600 - 2*256)/8

static const uint64_t _RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};
static const int _RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44,
};
static const int _PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1,
};
#define ROT64(x,n) (((x)<<(n))|((x)>>(64-(n))))

static void _keccak_f(uint64_t s[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t bc[5];
        for (int i = 0; i < 5; i++)
            bc[i] = s[i]^s[i+5]^s[i+10]^s[i+15]^s[i+20];
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i+4)%5] ^ ROT64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) s[j+i] ^= t;
        }
        uint64_t t = s[1], t2;
        for (int i = 0; i < 24; i++) {
            int j = _PI[i]; t2 = s[j];
            s[j] = ROT64(t, _RHO[i]); t = t2;
        }
        for (int j = 0; j < 25; j += 5) {
            uint64_t tmp[5];
            for (int i = 0; i < 5; i++) tmp[i] = s[j+i];
            for (int i = 0; i < 5; i++)
                s[j+i] = tmp[i] ^ ((~tmp[(i+1)%5]) & tmp[(i+2)%5]);
        }
        s[0] ^= _RC[r];
    }
}

typedef struct { uint64_t s[25]; uint8_t buf[SHA3_RATE]; uint32_t blen; } _sha3_ctx;

static void _sha3_absorb(_sha3_ctx *c, const uint8_t *in, size_t len) {
    while (len) {
        size_t take = len < (size_t)(SHA3_RATE - c->blen) ? len : (size_t)(SHA3_RATE - c->blen);
        memcpy(c->buf + c->blen, in, take);
        c->blen += take; in += take; len -= take;
        if (c->blen == SHA3_RATE) {
            for (int i = 0; i < SHA3_RATE/8; i++) {
                uint64_t w = 0;
                for (int b = 0; b < 8; b++) w |= (uint64_t)c->buf[i*8+b] << (b*8);
                c->s[i] ^= w;
            }
            _keccak_f(c->s); c->blen = 0;
        }
    }
}

static void _sha3_256(const uint8_t *in, size_t len, uint8_t out[32]) {
    _sha3_ctx c; memset(&c, 0, sizeof(c));
    _sha3_absorb(&c, in, len);
    memset(c.buf + c.blen, 0, SHA3_RATE - c.blen);
    c.buf[c.blen]        = 0x06;
    c.buf[SHA3_RATE - 1] ^= 0x80;
    for (int i = 0; i < SHA3_RATE/8; i++) {
        uint64_t w = 0;
        for (int b = 0; b < 8; b++) w |= (uint64_t)c.buf[i*8+b] << (b*8);
        c.s[i] ^= w;
    }
    _keccak_f(c.s);
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 8; b++)
            out[i*8+b] = (c.s[i] >> (b*8)) & 0xff;
}

// ═════════════════════════════════════════════════════════════════════════════
// §2  RLP encoder (Ethereum-compatible — Flow uses it for TX envelopes)
// ═════════════════════════════════════════════════════════════════════════════

static size_t _rlp_hdr(uint8_t base_short, uint8_t base_long,
                        size_t plen, uint8_t *out, size_t cap) {
    if (plen <= 55) {
        if (cap < 1) return 0;
        out[0] = (uint8_t)(base_short + plen); return 1;
    }
    uint8_t ll[8]; int ll_n = 0;
    for (size_t v = plen; v; v >>= 8) ll[ll_n++] = v & 0xff;
    for (int i = 0; i < ll_n/2; i++) { uint8_t t=ll[i]; ll[i]=ll[ll_n-1-i]; ll[ll_n-1-i]=t; }
    if (cap < 1+(size_t)ll_n) return 0;
    out[0] = (uint8_t)(base_long + ll_n);
    memcpy(out+1, ll, ll_n); return 1+ll_n;
}

static size_t _rlp_bytes(const uint8_t *d, size_t dlen, uint8_t *out, size_t cap) {
    if (dlen == 1 && d[0] < 0x80) { if (cap<1) return 0; out[0]=d[0]; return 1; }
    size_t hlen = _rlp_hdr(0x80, 0xb7, dlen, out, cap);
    if (!hlen || cap < hlen+dlen) return 0;
    memcpy(out+hlen, d, dlen); return hlen+dlen;
}

static size_t _rlp_u64(uint64_t v, uint8_t *out, size_t cap) {
    if (v == 0) { if (cap<1) return 0; out[0]=0x80; return 1; }
    uint8_t be[8]; int n=0;
    for (int i=7; i>=0; i--) { uint8_t b=(v>>(i*8))&0xff; if (b||n) be[n++]=b; }
    return _rlp_bytes(be, n, out, cap);
}

static size_t _rlp_list_hdr(size_t plen, uint8_t *out, size_t cap) {
    return _rlp_hdr(0xc0, 0xf7, plen, out, cap);
}

// ═════════════════════════════════════════════════════════════════════════════
// §3  Base64 encoder + decoder
// ═════════════════════════════════════════════════════════════════════════════
static const char _B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t _b64_enc(const uint8_t *in, size_t ilen, char *out, size_t ocap) {
    size_t n = 0;
    for (size_t i = 0; i < ilen; i += 3) {
        uint32_t v = (uint32_t)in[i]<<16;
        if (i+1<ilen) v |= (uint32_t)in[i+1]<<8;
        if (i+2<ilen) v |= in[i+2];
        size_t take = (ilen-i>=3)?4:(ilen-i==2)?3:2;
        if (n+4 >= ocap) return 0;
        out[n++] = _B64[(v>>18)&0x3f];
        out[n++] = _B64[(v>>12)&0x3f];
        out[n++] = (take>=3) ? _B64[(v>>6)&0x3f] : '=';
        out[n++] = (take>=4) ? _B64[(v   )&0x3f] : '=';
    }
    out[n]='\0'; return n;
}

// Decode a base64 string into raw bytes. Returns decoded length.
static const uint8_t _BD[256] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
};

static size_t _b64_dec(const char *in, size_t ilen, uint8_t *out, size_t ocap) {
    size_t n = 0;
    for (size_t i = 0; i+3 < ilen; i += 4) {
        uint8_t a=_BD[(uint8_t)in[i  ]], b=_BD[(uint8_t)in[i+1]],
                c=_BD[(uint8_t)in[i+2]], d=_BD[(uint8_t)in[i+3]];
        if (a==64||b==64) break;
        if (n<ocap) out[n++]=(a<<2)|(b>>4);
        if (in[i+2]!='='&&c!=64&&n<ocap) out[n++]=(b<<4)|(c>>2);
        if (in[i+3]!='='&&d!=64&&n<ocap) out[n++]=(c<<6)|d;
    }
    return n;
}

// ═════════════════════════════════════════════════════════════════════════════
// §4  HTTPS helpers (TLS, setInsecure — fine for testnet)
// ═════════════════════════════════════════════════════════════════════════════

static int _https_get(const char *path, char *rbuf, size_t rcap) {
    WiFiClientSecure cli; cli.setInsecure();
    if (!cli.connect(_api_host, 443)) {
        Serial.printf("[FlowTx] GET connect failed → %s\n", _api_host); return -1;
    }
    cli.printf("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, _api_host);
    uint32_t dl = millis()+12000;
    while (!cli.available() && millis()<dl) delay(10);
    String sl = cli.readStringUntil('\n'); int code=0;
    sscanf(sl.c_str(), "HTTP/%*s %d", &code);
    while (cli.connected()||cli.available()) { String h=cli.readStringUntil('\n'); if (h=="\r"||!h.length()) break; }
    size_t n=0;
    while ((cli.connected()||cli.available())&&n<rcap-1) { if (cli.available()) rbuf[n++]=cli.read(); }
    rbuf[n]='\0'; cli.stop(); return code;
}

static int _https_post(const char *path, const char *body,
                       char *rbuf, size_t rcap) {
    WiFiClientSecure cli; cli.setInsecure();
    if (!cli.connect(_api_host, 443)) {
        Serial.printf("[FlowTx] POST connect failed → %s\n", _api_host); return -1;
    }
    cli.printf("POST %s HTTP/1.0\r\nHost: %s\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n%s",
               path, _api_host, (int)strlen(body), body);
    uint32_t dl = millis()+12000;
    while (!cli.available()&&millis()<dl) delay(10);
    String sl = cli.readStringUntil('\n'); int code=0;
    sscanf(sl.c_str(), "HTTP/%*s %d", &code);
    while (cli.connected()||cli.available()) { String h=cli.readStringUntil('\n'); if (h=="\r"||!h.length()) break; }
    size_t n=0;
    while ((cli.connected()||cli.available())&&n<rcap-1) { if (cli.available()) rbuf[n++]=cli.read(); }
    rbuf[n]='\0'; cli.stop(); return code;
}

// ═════════════════════════════════════════════════════════════════════════════
// §5  Hex utilities
// ═════════════════════════════════════════════════════════════════════════════
static int _hnib(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static bool _hex_to_bytes(const char *hex, size_t hlen, uint8_t *out) {
    if (hlen&1) return false;
    for (size_t i=0; i<hlen; i+=2) {
        int hi=_hnib(hex[i]), lo=_hnib(hex[i+1]);
        if (hi<0||lo<0) return false;
        out[i/2]=(uint8_t)((hi<<4)|lo);
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// §6  Flow REST helpers — fetch reference block ID and sequence number
// ═════════════════════════════════════════════════════════════════════════════
static bool _get_ref_block(uint8_t ref_id[32]) {
    static char rbuf[1024];
    int code = _https_get("/v1/blocks?height=sealed", rbuf, sizeof(rbuf));
    if (code != 200) { Serial.printf("[FlowTx] get_ref_block HTTP %d\n", code); return false; }
    const char *p = strstr(rbuf, "\"id\":\"");
    if (!p) { Serial.println("[FlowTx] get_ref_block: no id field"); return false; }
    p += 6;
    if (strlen(p) < 64) { Serial.println("[FlowTx] get_ref_block: id too short"); return false; }
    return _hex_to_bytes(p, 64, ref_id);
}

static bool _get_seq_num(uint64_t *seq_out) {
    static char path[80], rbuf[2048];
    const char *addr = _account_addr;
    if (addr[0]=='0'&&addr[1]=='x') addr+=2;
    snprintf(path, sizeof(path), "/v1/accounts/0x%s?expand=keys", addr);
    int code = _https_get(path, rbuf, sizeof(rbuf));
    if (code != 200) { Serial.printf("[FlowTx] get_seq_num HTTP %d\n", code); return false; }
    const char *p = strstr(rbuf, "\"sequence_number\":\"");
    if (!p) { Serial.println("[FlowTx] get_seq_num: field missing"); return false; }
    p += 19;
    *seq_out = (uint64_t)atoll(p);
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// §7  RLP payload + envelope construction
// ═════════════════════════════════════════════════════════════════════════════

// "FLOW-V0.0-transaction\x00..." padded to 32 bytes
// "FLOW-V0.0-transaction" = 21 bytes, so 11 trailing null bytes
static const uint8_t _DOMAIN_TAG[32] = {
    'F','L','O','W','-','V','0','.','0','-',
    't','r','a','n','s','a','c','t','i','o','n',
    0,0,0,0,0,0,0,0,0,0,0
};

typedef struct {
    const char  *script;
    const char **args_json;  // array of Cadence JSON strings, already serialised
    int          n_args;
    uint32_t     gas_limit;
} _tx_params;

static size_t _build_rlp_payload(const _tx_params *p, const uint8_t ref_id[32],
                                   uint64_t seq_num, uint8_t *out, size_t cap) {
    static uint8_t stg[8192];
    size_t pos = 0;

#define W(fn, ...) do { \
    size_t _n = fn(__VA_ARGS__, stg+pos, sizeof(stg)-pos); \
    if (!_n) { Serial.println("[FlowTx] RLP overflow"); return 0; } \
    pos += _n; \
} while(0)

    // 1. script
    W(_rlp_bytes, (const uint8_t*)p->script, strlen(p->script));

    // 2. arguments list
    {
        static uint8_t arg_stg[4096]; size_t apos=0;
        for (int i=0; i<p->n_args; i++) {
            size_t n = _rlp_bytes((const uint8_t*)p->args_json[i],
                                   strlen(p->args_json[i]),
                                   arg_stg+apos, sizeof(arg_stg)-apos);
            if (!n) { Serial.println("[FlowTx] arg RLP overflow"); return 0; }
            apos += n;
        }
        size_t hn = _rlp_list_hdr(apos, stg+pos, sizeof(stg)-pos);
        if (!hn) return 0;
        pos += hn;
        memcpy(stg+pos, arg_stg, apos); pos += apos;
    }

    // 3. reference block ID
    W(_rlp_bytes, ref_id, 32);
    // 4. gas limit
    W(_rlp_u64,   (uint64_t)p->gas_limit);
    // 5. proposer address
    W(_rlp_bytes, _account_raw, 8);
    // 6. proposer key index = 0
    W(_rlp_u64,   (uint64_t)0);
    // 7. sequence number
    W(_rlp_u64,   seq_num);
    // 8. payer address
    W(_rlp_bytes, _account_raw, 8);

    // 9. authorizers list: [[addr_bytes]]
    {
        static uint8_t ai[16], ao[32];
        size_t in  = _rlp_bytes(_account_raw, 8, ai, sizeof(ai));
        size_t hni = _rlp_list_hdr(in, ao, sizeof(ao));
        memcpy(ao+hni, ai, in);
        size_t inner_len = hni+in;
        size_t hno = _rlp_list_hdr(inner_len, stg+pos, sizeof(stg)-pos);
        if (!hno) return 0;
        pos += hno;
        memcpy(stg+pos, ao, inner_len); pos += inner_len;
    }
#undef W

    // Wrap in outer payload list
    size_t hn = _rlp_list_hdr(pos, out, cap);
    if (!hn || cap < hn+pos) return 0;
    memcpy(out+hn, stg, pos); return hn+pos;
}

static bool _sign_envelope(const uint8_t *payload_rlp, size_t plen, uint8_t sig_out[64]) {
    static uint8_t env[12288];
    size_t pos = 0;

    memcpy(env, _DOMAIN_TAG, 32); pos = 32;

    // Outer list: [payload_rlp, []]  — [] = 0xc0
    size_t inner_len = plen + 1;
    size_t hn = _rlp_list_hdr(inner_len, env+pos, sizeof(env)-pos);
    if (!hn) { Serial.println("[FlowTx] envelope overflow"); return false; }
    pos += hn;
    memcpy(env+pos, payload_rlp, plen); pos += plen;
    env[pos++] = 0xc0;  // empty payload_signatures array

    if (pos > sizeof(env)) { Serial.println("[FlowTx] env buf overflow"); return false; }

    uint8_t hash[32];
    _sha3_256(env, pos, hash);

    if (!uECC_sign(_priv, hash, 32, sig_out, uECC_secp256r1())) {
        Serial.println("[FlowTx] uECC_sign failed"); return false;
    }
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// §8  Cadence argument builders
//     Each returns a pointer into a per-slot static buffer.
//     Up to 6 slots — sufficient for all transactions in this project.
// ═════════════════════════════════════════════════════════════════════════════
static char _as[6][768];  // argument scratch, 6 slots

static const char *_cstr(int slot, const char *v) {
    snprintf(_as[slot], sizeof(_as[slot]), "{\"type\":\"String\",\"value\":\"%s\"}", v);
    return _as[slot];
}
static const char *_cufix(int slot, double v) {
    snprintf(_as[slot], sizeof(_as[slot]), "{\"type\":\"UFix64\",\"value\":\"%.8f\"}", v);
    return _as[slot];
}
static char _arr_scratch[2048];
static const char *_cstr_arr(const char **vals, int n) {
    int p=0;
    p+=snprintf(_arr_scratch+p, sizeof(_arr_scratch)-p, "{\"type\":\"Array\",\"value\":[");
    for (int i=0; i<n; i++) {
        if (i) p+=snprintf(_arr_scratch+p, sizeof(_arr_scratch)-p, ",");
        p+=snprintf(_arr_scratch+p, sizeof(_arr_scratch)-p,
                    "{\"type\":\"String\",\"value\":\"%s\"}", vals[i]);
    }
    p+=snprintf(_arr_scratch+p, sizeof(_arr_scratch)-p, "]}");
    return _arr_scratch;
}

// ═════════════════════════════════════════════════════════════════════════════
// §9  Script template expansion — substitute {CONTRACT} placeholder
// ═════════════════════════════════════════════════════════════════════════════
static char _script_buf[1280];
static const char *_expand(const char *tmpl) {
    const char *p = strstr(tmpl, "{CONTRACT}");
    if (!p) { strncpy(_script_buf, tmpl, sizeof(_script_buf)); return _script_buf; }
    size_t pre = p - tmpl;
    snprintf(_script_buf, sizeof(_script_buf), "%.*s%s%s",
             (int)pre, tmpl, _contract_addr, p+10);
    return _script_buf;
}

// ═════════════════════════════════════════════════════════════════════════════
// §10  Core TX submission — build, sign, POST, optionally poll for seal
// ═════════════════════════════════════════════════════════════════════════════

static bool _submit_tx(const _tx_params *p, bool wait_seal, char tx_id_out[65]) {
    uint8_t  ref_id[32]; uint64_t seq_num;
    if (!_get_ref_block(ref_id)) return false;
    if (!_get_seq_num(&seq_num))  return false;

    static uint8_t payload_rlp[8192];
    size_t plen = _build_rlp_payload(p, ref_id, seq_num, payload_rlp, sizeof(payload_rlp));
    if (!plen) return false;

    uint8_t sig[64];
    if (!_sign_envelope(payload_rlp, plen, sig)) return false;

    // Base64-encode script
    static char script_b64[1280];
    _b64_enc((const uint8_t*)p->script, strlen(p->script), script_b64, sizeof(script_b64));

    // Base64-encode each argument
    static char arg_b64[6][1024];
    for (int i=0; i<p->n_args && i<6; i++)
        _b64_enc((const uint8_t*)p->args_json[i], strlen(p->args_json[i]),
                  arg_b64[i], sizeof(arg_b64[i]));

    // Base64-encode signature
    static char sig_b64[128];
    _b64_enc(sig, 64, sig_b64, sizeof(sig_b64));

    // Reference block ID as hex (REST API wants hex, not base64)
    static char ref_hex[65];
    for (int i=0; i<32; i++) snprintf(ref_hex+i*2, 3, "%02x", ref_id[i]);

    // Canonical account address with 0x prefix
    const char *raw = _account_addr;
    if (raw[0]=='0'&&raw[1]=='x') raw+=2;
    static char addr0x[24]; snprintf(addr0x, sizeof(addr0x), "0x%s", raw);

    // Build arguments JSON array
    static char args_arr[4096]; int ap=0;
    ap+=snprintf(args_arr+ap, sizeof(args_arr)-ap, "[");
    for (int i=0; i<p->n_args&&i<6; i++) {
        if (i) ap+=snprintf(args_arr+ap, sizeof(args_arr)-ap, ",");
        ap+=snprintf(args_arr+ap, sizeof(args_arr)-ap, "\"%s\"", arg_b64[i]);
    }
    ap+=snprintf(args_arr+ap, sizeof(args_arr)-ap, "]");

    // Assemble POST body
    static char body[8192];
    snprintf(body, sizeof(body),
        "{"
        "\"script\":\"%s\","
        "\"arguments\":%s,"
        "\"reference_block_id\":\"%s\","
        "\"gas_limit\":\"9999\","
        "\"proposal_key\":{"
            "\"address\":\"%s\","
            "\"key_index\":\"0\","
            "\"sequence_number\":\"%llu\""
        "},"
        "\"payer\":\"%s\","
        "\"authorizers\":[\"%s\"],"
        "\"payload_signatures\":[],"
        "\"envelope_signatures\":[{"
            "\"address\":\"%s\","
            "\"key_index\":\"0\","
            "\"signature\":\"%s\""
        "}]"
        "}",
        script_b64, args_arr, ref_hex,
        addr0x, (unsigned long long)seq_num,
        addr0x, addr0x, addr0x, sig_b64);

    static char resp[1024];
    int code = _https_post("/v1/transactions", body, resp, sizeof(resp));
    if (code!=200 && code!=201) {
        Serial.printf("[FlowTx] POST /v1/transactions HTTP %d\n", code);
        Serial.printf("[FlowTx] %.300s\n", resp);
        return false;
    }

    // Extract tx ID
    const char *idp = strstr(resp, "\"id\":\"");
    if (!idp) { Serial.println("[FlowTx] no id in response"); return false; }
    idp += 6; strncpy(tx_id_out, idp, 64); tx_id_out[64]='\0';
    Serial.printf("[FlowTx] TX %s\n", tx_id_out);
    Serial.printf("[FlowTx]   https://testnet.flowscan.io/tx/%s\n", tx_id_out);

    if (!wait_seal) return true;

    // Poll for seal (max 60 s)
    static char poll_path[128], poll_resp[512];
    snprintf(poll_path, sizeof(poll_path), "/v1/transactions/%s/results", tx_id_out);
    uint32_t deadline = millis()+60000;
    while (millis()<deadline) {
        delay(3000);
        if (_https_get(poll_path, poll_resp, sizeof(poll_resp)) == 200) {
            if (strstr(poll_resp,"\"SEALED\"")||strstr(poll_resp,"\"Sealed\"")||strstr(poll_resp,"\"sealed\""))
                { Serial.println("[FlowTx] ✓ SEALED"); return true; }
            if (strstr(poll_resp,"\"FAILED\"")||strstr(poll_resp,"\"Failed\""))
                { Serial.println("[FlowTx] ✗ FAILED"); return false; }
        }
    }
    Serial.println("[FlowTx] ✗ Seal timeout (60 s)");
    return false;
}

// ═════════════════════════════════════════════════════════════════════════════
// §11  Public API
// ═════════════════════════════════════════════════════════════════════════════

void flow_tx_init(const uint8_t *priv_32, const char *account_addr,
                  const char *contract_addr, const char *api_host) {
    memcpy(_priv, priv_32, 32);
    strncpy(_account_addr,  account_addr,  sizeof(_account_addr)-1);
    strncpy(_contract_addr, contract_addr, sizeof(_contract_addr)-1);
    strncpy(_api_host,      api_host,      sizeof(_api_host)-1);

    // Parse 8-byte raw address for RLP (strip "0x", left-pad to 16 hex = 8 bytes)
    const char *hex = account_addr;
    if (hex[0]=='0'&&hex[1]=='x') hex+=2;
    char padded[17]="0000000000000000"; size_t hlen=strlen(hex);
    if (hlen<=16) memcpy(padded+(16-hlen), hex, hlen);
    _hex_to_bytes(padded, 16, _account_raw);

    Serial.printf("[FlowTx] init  account=%s  contract=%s\n", account_addr, contract_addr);
}

// ── registerNode ──────────────────────────────────────────────────────────────
bool flow_tx_register_node(const char *node_id, double stake_flow) {
    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "transaction(nodeId: String, stake: UFix64) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute { SwarmVerifierV3.registerNode(nodeId: nodeId, stake: stake) }\n"
        "}"
    );
    const char *args[2] = { _cstr(0,node_id), _cufix(1,stake_flow) };
    _tx_params p = { script, args, 2, 9999 };
    char tx_id[65]; bool ok = _submit_tx(&p, /*wait_seal=*/true, tx_id);
    if (ok) Serial.printf("[FlowTx] registerNode sealed: %.16s...\n", tx_id);
    return ok;
}

// ── registerAnomaly ───────────────────────────────────────────────────────────
bool flow_tx_register_anomaly(const char *transporter_pub_hex,
                               const char *submission_sig_hex,
                               float anomaly_confidence,
                               const char **quorum_ids, int n_quorum,
                               float payment_per_auditor) {
    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "transaction(\n"
        "    transporterId: String, submissionSig: String,\n"
        "    anomalyConfidence: UFix64, quorumIds: [String], paymentPerAuditor: UFix64\n"
        ") {\n"
        "    let gw: &SwarmVerifierV3.Gateway\n"
        "    prepare(signer: auth(Storage) &Account) {\n"
        "        self.gw = signer.storage.borrow<&SwarmVerifierV3.Gateway>(\n"
        "            from: SwarmVerifierV3.GatewayStoragePath\n"
        "        ) ?? panic(\"No Gateway\")\n"
        "    }\n"
        "    execute {\n"
        "        self.gw.registerAnomaly(\n"
        "            transporterId: transporterId, submissionSig: submissionSig,\n"
        "            anomalyConfidence: anomalyConfidence, quorumIds: quorumIds,\n"
        "            paymentPerAuditor: paymentPerAuditor\n"
        "        )\n"
        "    }\n"
        "}"
    );
    const char *args[5] = {
        _cstr(0, transporter_pub_hex),
        _cstr(1, submission_sig_hex),
        _cufix(2, (double)anomaly_confidence),
        _cstr_arr(quorum_ids, n_quorum),
        _cufix(4, (double)payment_per_auditor),
    };
    _tx_params p = { script, args, 5, 9999 };
    char tx_id[65];
    // wait_seal=true — PKT_QUORUM must not fire before PendingEvent exists on-chain
    bool ok = _submit_tx(&p, /*wait_seal=*/true, tx_id);
    if (ok) Serial.printf("[FlowTx] registerAnomaly sealed: %.16s...\n", tx_id);
    return ok;
}

// ── submitDeposit ─────────────────────────────────────────────────────────────
// Called in _handle_POST_pay() after nonce verification, before CSV is streamed.
// wait_seal=true: the deposit lock must be confirmed before data is released.
// If this returns false the caller must respond 503 — no data without escrow.
bool flow_tx_submit_deposit(const char *event_id, const char *auditor_pub_hex,
                             float deposit_amount, float bid_amount) {
    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "transaction(eventId: String, auditorId: String, deposit: UFix64, bid: UFix64) {\n"
        "    let gw: &SwarmVerifierV3.Gateway\n"
        "    prepare(signer: auth(Storage) &Account) {\n"
        "        self.gw = signer.storage.borrow<&SwarmVerifierV3.Gateway>(\n"
        "            from: SwarmVerifierV3.GatewayStoragePath\n"
        "        ) ?? panic(\"No Gateway\")\n"
        "    }\n"
        "    execute {\n"
        "        self.gw.submitDeposit(\n"
        "            eventId: eventId, auditorId: auditorId,\n"
        "            deposit: deposit, bid: bid\n"
        "        )\n"
        "    }\n"
        "}"
    );
    const char *args[4] = {
        _cstr(0, event_id),
        _cstr(1, auditor_pub_hex),
        _cufix(2, (double)deposit_amount),
        _cufix(3, (double)bid_amount),
    };
    _tx_params p = { script, args, 4, 9999 };
    char tx_id[65];
    bool ok = _submit_tx(&p, /*wait_seal=*/true, tx_id);
    if (ok) Serial.printf("[FlowTx] submitDeposit sealed: %.16s...\n", tx_id);
    return ok;
}

// ── finalizeEvent ─────────────────────────────────────────────────────────────
bool flow_tx_finalize_event(const char *event_id) {
    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "transaction(eventId: String) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute { SwarmVerifierV3.finalizeEvent(eventId: eventId) }\n"
        "}"
    );
    const char *args[1] = { _cstr(0, event_id) };
    _tx_params p = { script, args, 1, 9999 };
    char tx_id[65];
    return _submit_tx(&p, /*wait_seal=*/false, tx_id);
}

// ── updateEventCid ────────────────────────────────────────────────────────────
bool flow_tx_update_cid(const char *event_id, const char *cid) {
    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "transaction(eventId: String, cid: String) {\n"
        "    let gw: &SwarmVerifierV3.Gateway\n"
        "    prepare(signer: auth(Storage) &Account) {\n"
        "        self.gw = signer.storage.borrow<&SwarmVerifierV3.Gateway>(\n"
        "            from: SwarmVerifierV3.GatewayStoragePath\n"
        "        ) ?? panic(\"No Gateway\")\n"
        "    }\n"
        "    execute { self.gw.updateEventCid(eventId: eventId, cid: cid) }\n"
        "}"
    );
    const char *args[2] = { _cstr(0, event_id), _cstr(1, cid) };
    _tx_params p = { script, args, 2, 9999 };
    char tx_id[65];
    return _submit_tx(&p, /*wait_seal=*/false, tx_id);
}

// ── queryNode — read-only Cadence script, no signing ─────────────────────────
bool flow_tx_query_node(const char *pub_hex, float *stake_out, float *rep_out) {
    *stake_out = 0.0f; *rep_out = 0.0f;

    const char *script = _expand(
        "import SwarmVerifierV3 from {CONTRACT}\n"
        "access(all) fun main(nodeId: String): [AnyStruct] {\n"
        "    let s = SwarmVerifierV3.getStake(nodeId: nodeId)      ?? 0.0\n"
        "    let r = SwarmVerifierV3.getReputation(nodeId: nodeId) ?? Fix64(0)\n"
        "    return [s, r]\n"
        "}"
    );

    static char script_b64[1280];
    _b64_enc((const uint8_t*)script, strlen(script), script_b64, sizeof(script_b64));

    static char arg_json[256], arg_b64[512];
    snprintf(arg_json, sizeof(arg_json),
             "{\"type\":\"String\",\"value\":\"%s\"}", pub_hex);
    _b64_enc((const uint8_t*)arg_json, strlen(arg_json), arg_b64, sizeof(arg_b64));

    static char body[2048];
    snprintf(body, sizeof(body),
             "{\"script\":\"%s\",\"arguments\":[\"%s\"]}", script_b64, arg_b64);

    static char resp[1024];
    int code = _https_post("/v1/scripts", body, resp, sizeof(resp));
    if (code != 200) { Serial.printf("[FlowTx] queryNode HTTP %d\n", code); return false; }

    // Response: {"value": "<base64 Cadence JSON>"}
    // Decoded: {"type":"Array","value":[{"type":"UFix64","value":"10.00000000"},
    //                                   {"type":"Fix64", "value":"0.00000000"}]}
    const char *vp = strstr(resp, "\"value\":\"");
    if (!vp) return false;
    vp += 9;

    static char decoded[512];
    const char *end = strchr(vp, '"');
    size_t b64len = end ? (size_t)(end-vp) : strlen(vp);
    size_t dlen = _b64_dec(vp, b64len, (uint8_t*)decoded, sizeof(decoded)-1);
    decoded[dlen] = '\0';

    // Extract first and second numeric value fields from the decoded Cadence JSON
    const char *first = strstr(decoded, "\"value\":\"");
    if (first) {
        first += 9; *stake_out = (float)atof(first);
        const char *second = strstr(first, "\"value\":\"");
        if (second) { second += 9; *rep_out = (float)atof(second); }
    }
    Serial.printf("[FlowTx] queryNode  stake=%.2f  rep=%.4f\n", *stake_out, *rep_out);
    return true;
}