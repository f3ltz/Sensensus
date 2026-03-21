#!/usr/bin/env python3
"""
flow_relay.py  —  Flow blockchain relay for the Pico 2W transporter.
Architecture: PL_Genesis Hackathon 2026

The Pico cannot implement Flow's SHA3-256 + RLP transaction envelope in C,
so it delegates all on-chain calls to this relay over plain local HTTP.
Run alongside mock_transporter.py on the same laptop.

Endpoints
---------
POST /flow/register-anomaly
  Body: {
    "transporter_pub_hex": str,   # 128-char hex
    "submission_sig_hex":  str,   # 128-char hex  (used as eventId on-chain)
    "anomaly_confidence":  float, # 0.0 – 1.0
    "quorum_ids":          [str], # auditor pubkey hexes
    "payment_per_auditor": float  # FLOW tokens
  }
  → 200 { "tx_id": "<hex>", "sealed": bool }
  → 500 { "error": "..." }

POST /flow/update-cid
  Body: { "event_id": str, "cid": str }
  → 200 { "tx_id": "<hex>" }
  → 500 { "error": "..." }

GET  /flow/query-node?pub_hex=<128-char-hex>
  → 200 { "stake": float, "reputation": float }
  → 500 { "error": "..." }

GET  /health
  → 200 { "status": "ok", "flow_enabled": bool, "account": str }

Environment variables
---------------------
  RELAY_PORT          – port to listen on (default 8090)
  FLOW_API_URL        – Flow gRPC access node (default devnet)
  FLOW_CONTRACT_ADDR  – SwarmVerifierV4 address on testnet
  FLOW_ACCOUNT_ADDR   – deployer account address (holds Gateway resource)
  FLOW_ACCOUNT_KEY    – hex-encoded secp256r1 private key for that account
  PAYMENT_PER_AUDITOR – default payment in FLOW if not supplied in body (default 1.0)
"""

import asyncio
import base64
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import requests
from dotenv import load_dotenv
from ecdsa import NIST256p, SigningKey
from ecdsa.util import sigencode_string
from flow_py_sdk import flow_client
from flow_py_sdk.cadence import String, UFix64, Array
from flow_py_sdk.tx import Tx, ProposalKey
from flow_py_sdk.signer import Signer as FlowSigner

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
RELAY_PORT          = int(os.environ.get("RELAY_PORT", "8090"))
FLOW_API_HOST       = os.environ.get("FLOW_API_HOST", "access.devnet.nodes.onflow.org")
FLOW_API_GRPC_PORT  = int(os.environ.get("FLOW_API_GRPC_PORT", "9000"))
FLOW_REST_URL       = os.environ.get("FLOW_REST_URL", "https://rest-testnet.onflow.org")
FLOW_CONTRACT_ADDR  = os.environ.get("FLOW_CONTRACT_ADDR", "")
FLOW_ACCOUNT_ADDR   = os.environ.get("FLOW_ACCOUNT_ADDR", "")
FLOW_ACCOUNT_KEY    = os.environ.get("FLOW_ACCOUNT_KEY", "")
PAYMENT_PER_AUDITOR = float(os.environ.get("PAYMENT_PER_AUDITOR", "1.0"))

FLOW_ENABLED = bool(FLOW_ACCOUNT_ADDR and FLOW_ACCOUNT_KEY and FLOW_CONTRACT_ADDR)

# ── Cadence transactions (sourced from mock_transporter.py) ───────────────────

def _REGISTER_ANOMALY_TX():
    return (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(\n"
        "    transporterId:     String,\n"
        "    submissionSig:     String,\n"
        "    anomalyConfidence: UFix64,\n"
        "    quorumIds:         [String],\n"
        "    paymentPerAuditor: UFix64\n"
        ") {\n"
        "    let gateway: &SwarmVerifierV4.Gateway\n"
        "    prepare(signer: auth(Storage) &Account) {\n"
        "        self.gateway = signer.storage.borrow<&SwarmVerifierV4.Gateway>(\n"
        "            from: SwarmVerifierV4.GatewayStoragePath\n"
        "        ) ?? panic(\"No Gateway resource\")\n"
        "    }\n"
        "    execute {\n"
        "        self.gateway.registerAnomaly(\n"
        "            transporterId:     transporterId,\n"
        "            submissionSig:     submissionSig,\n"
        "            anomalyConfidence: anomalyConfidence,\n"
        "            quorumIds:         quorumIds,\n"
        "            paymentPerAuditor: paymentPerAuditor\n"
        "        )\n"
        "    }\n"
        "}"
    )


def _UPDATE_CID_TX():
    return (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String, cid: String) {\n"
        "    let gateway: &SwarmVerifierV4.Gateway\n"
        "    prepare(signer: auth(Storage) &Account) {\n"
        "        self.gateway = signer.storage.borrow<&SwarmVerifierV4.Gateway>(\n"
        "            from: SwarmVerifierV4.GatewayStoragePath\n"
        "        ) ?? panic(\"No Gateway resource\")\n"
        "    }\n"
        "    execute {\n"
        "        self.gateway.updateEventCid(eventId: eventId, cid: cid)\n"
        "    }\n"
        "}"
    )


def _QUERY_NODE_SCRIPT():
    return (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "access(all) fun main(nodeId: String): [AnyStruct] {\n"
        "    let stake = SwarmVerifierV4.getStake(nodeId: nodeId) ?? 0.0\n"
        "    let rep   = SwarmVerifierV4.getReputation(nodeId: nodeId) ?? Fix64(0)\n"
        "    return [stake, rep]\n"
        "}"
    )


# ── ECDSA signer (secp256r1 / P-256 + SHA3-256, as Flow requires) ─────────────

class _P256Signer(FlowSigner):
    def __init__(self, sk: SigningKey):
        self._sk = sk

    def sign(self, message: bytes, tag: bytes | None = None) -> bytes:
        if tag is not None:
            message = tag + message
        return self._sk.sign(
            message,
            hashfunc=hashlib.sha3_256,
            sigencode=sigencode_string,
        )


def _load_signer() -> _P256Signer | None:
    if not FLOW_ACCOUNT_KEY:
        return None
    try:
        sk = SigningKey.from_string(bytes.fromhex(FLOW_ACCOUNT_KEY), curve=NIST256p)
        return _P256Signer(sk)
    except Exception as e:
        print(f"[Relay] ⚠  Could not load signing key: {e}")
        return None


_signer = _load_signer()

# ── Flow transaction submission ────────────────────────────────────────────────

async def _flow_tx_async(cadence: str, build_fn, label: str, wait_seal: bool = True):
    """Submit a Flow transaction. Returns tx_id str on success, raises on failure."""
    flow_addr = FLOW_ACCOUNT_ADDR.lstrip("0x")

    for attempt in range(3):
        try:
            async with flow_client(host=FLOW_API_HOST, port=FLOW_API_GRPC_PORT) as client:
                account     = await client.get_account(address=bytes.fromhex(flow_addr))
                account_key = account.keys[0]
                seq_num     = account_key.sequence_number

                tx = (
                    Tx(
                        code=cadence,
                        reference_block_id=None,
                        payer=FLOW_ACCOUNT_ADDR,
                        proposal_key=ProposalKey(
                            key_address=FLOW_ACCOUNT_ADDR,
                            key_id=0,
                            key_sequence_number=seq_num,
                        ),
                    )
                    .add_authorizers(FLOW_ACCOUNT_ADDR)
                )
                tx = build_fn(tx)
                tx = tx.with_envelope_signature(
                    signer=_signer,
                    address=FLOW_ACCOUNT_ADDR,
                    key_id=0,
                )

                timeout = 60.0 if wait_seal else 30.0
                result  = await client.execute_transaction(
                    tx, wait_for_seal=wait_seal, timeout=timeout
                )
                tx_id = result.id.hex() if hasattr(result.id, "hex") else str(result.id)
                print(f"[Relay] ✓ {label} → TX {tx_id}")
                print(f"[Relay]   https://testnet.flowscan.io/tx/{tx_id}")
                return tx_id

        except Exception as e:
            err = str(e)
            if "sequence number" in err and attempt < 2:
                print(f"[Relay] Sequence number mismatch on attempt {attempt + 1}, retrying in 2s...")
                await asyncio.sleep(2)
                continue
            if "already registered" in err:
                print(f"[Relay] {label} — already on-chain, skipping.")
                return None
            raise


# ── Flow script query (via REST API) ──────────────────────────────────────────

def _run_flow_script(cadence: str, arguments: list[dict]) -> dict:
    """
    Execute a read-only Cadence script via Flow REST API.
    arguments: list of Cadence value dicts, e.g. {"type": "String", "value": "abc"}
    Returns the decoded Cadence JSON result dict.
    """
    encoded_script = base64.b64encode(cadence.encode()).decode()
    encoded_args   = [
        base64.b64encode(json.dumps(arg).encode()).decode()
        for arg in arguments
    ]
    resp = requests.post(
        f"{FLOW_REST_URL}/v1/scripts",
        json={"script": encoded_script, "arguments": encoded_args},
        timeout=10,
    )
    resp.raise_for_status()
    # Response: { "value": "<base64-encoded Cadence JSON>" }
    raw_value = resp.json().get("value", "")
    decoded   = base64.b64decode(raw_value).decode()
    return json.loads(decoded)


# ── HTTP request handler ───────────────────────────────────────────────────────

class RelayHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[Relay] {self.address_string()}  {fmt % args}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    # ── GET ───────────────────────────────────────────────────────────────────

    def do_GET(self):
        parsed = urlparse(self.path)
        qs     = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send_json(200, {
                "status":       "ok",
                "flow_enabled": FLOW_ENABLED,
                "account":      FLOW_ACCOUNT_ADDR or "(not set)",
                "contract":     FLOW_CONTRACT_ADDR or "(not set)",
            })
            return

        if parsed.path == "/flow/query-node":
            pub_hex = qs.get("pub_hex", [""])[0]
            if not pub_hex:
                self._send_json(400, {"error": "missing pub_hex query param"})
                return
            self._handle_query_node(pub_hex)
            return

        self._send_json(404, {"error": "not found"})

    # ── POST ──────────────────────────────────────────────────────────────────

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        if body is None:
            self._send_json(400, {"error": "invalid JSON body"})
            return

        if path == "/flow/register-anomaly":
            self._handle_register_anomaly(body)
        elif path == "/flow/update-cid":
            self._handle_update_cid(body)
        else:
            self._send_json(404, {"error": "not found"})

    # ── Handler: registerAnomaly ──────────────────────────────────────────────

    def _handle_register_anomaly(self, body: dict):
        required = [
            "transporter_pub_hex", "submission_sig_hex",
            "anomaly_confidence",  "quorum_ids",
        ]
        missing = [f for f in required if f not in body]
        if missing:
            self._send_json(400, {"error": f"missing fields: {missing}"}); return

        payment = float(body.get("payment_per_auditor", PAYMENT_PER_AUDITOR))

        if not FLOW_ENABLED:
            sim_id = "SIM_" + body["submission_sig_hex"][:16]
            print(f"[Relay] (sim) registerAnomaly "
                  f"event={body['submission_sig_hex'][:16]}... "
                  f"quorum={len(body['quorum_ids'])}  "
                  f"conf={body['anomaly_confidence']:.4f}")
            self._send_json(200, {"tx_id": sim_id, "sealed": True})
            return

        cadence       = _REGISTER_ANOMALY_TX()
        conf_ufix64   = int(round(float(body["anomaly_confidence"]) * 1e8))
        payment_ufix  = int(round(payment * 1e8))
        quorum_ids    = list(body["quorum_ids"])

        def build(tx):
            tx = tx.add_arguments(String(body["transporter_pub_hex"]))
            tx = tx.add_arguments(String(body["submission_sig_hex"]))
            tx = tx.add_arguments(UFix64(conf_ufix64))
            tx = tx.add_arguments(Array([String(qid) for qid in quorum_ids]))
            tx = tx.add_arguments(UFix64(payment_ufix))
            return tx

        try:
            # wait_seal=True: auditors must not get PKT_QUORUM until event exists on-chain
            tx_id = asyncio.run(_flow_tx_async(cadence, build, "registerAnomaly", wait_seal=True))
            self._send_json(200, {"tx_id": tx_id or "", "sealed": True})
        except Exception as e:
            print(f"[Relay] registerAnomaly error: {e}")
            self._send_json(500, {"error": str(e)})

    # ── Handler: updateEventCid ───────────────────────────────────────────────

    def _handle_update_cid(self, body: dict):
        if "event_id" not in body or "cid" not in body:
            self._send_json(400, {"error": "missing event_id or cid"}); return

        if not FLOW_ENABLED:
            print(f"[Relay] (sim) updateEventCid "
                  f"event={body['event_id'][:16]}...  cid={body['cid']}")
            self._send_json(200, {"tx_id": "SIM_CID_UPDATE"})
            return

        cadence = _UPDATE_CID_TX()

        def build(tx):
            tx = tx.add_arguments(String(body["event_id"]))
            tx = tx.add_arguments(String(body["cid"]))
            return tx

        try:
            tx_id = asyncio.run(_flow_tx_async(cadence, build, "updateEventCid", wait_seal=False))
            self._send_json(200, {"tx_id": tx_id or ""})
        except Exception as e:
            print(f"[Relay] updateEventCid error: {e}")
            self._send_json(500, {"error": str(e)})

    # ── Handler: queryNode ────────────────────────────────────────────────────

    def _handle_query_node(self, pub_hex: str):
        if not FLOW_ENABLED:
            self._send_json(200, {"stake": 0.0, "reputation": 0.0})
            return

        cadence = _QUERY_NODE_SCRIPT()
        arg     = {"type": "String", "value": pub_hex}

        try:
            result = _run_flow_script(cadence, [arg])
            # Cadence Array response: [{"type":"UFix64","value":"10.00000000"}, ...]
            vals       = result.get("value", [])
            stake_str  = vals[0]["value"] if len(vals) > 0 else "0.0"
            rep_str    = vals[1]["value"] if len(vals) > 1 else "0.0"
            self._send_json(200, {
                "stake":      float(stake_str),
                "reputation": float(rep_str),
            })
        except Exception as e:
            print(f"[Relay] queryNode error: {e}")
            self._send_json(500, {"error": str(e)})


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  SwarmVerifier Flow Relay")
    print("=" * 60)
    if FLOW_ENABLED:
        print(f"  Account:  {FLOW_ACCOUNT_ADDR}")
        print(f"  Contract: {FLOW_CONTRACT_ADDR}")
        print(f"  gRPC:     {FLOW_API_HOST}:{FLOW_API_GRPC_PORT}")
        print(f"  REST:     {FLOW_REST_URL}")
    else:
        print("  FLOW_ENABLED=False — simulation mode.")
        print("  Set FLOW_ACCOUNT_ADDR, FLOW_ACCOUNT_KEY, FLOW_CONTRACT_ADDR to go live.")
    print(f"  Listening on 0.0.0.0:{RELAY_PORT}")
    print("=" * 60)

    server = HTTPServer(("0.0.0.0", RELAY_PORT), RelayHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Relay] Shutting down.")


if __name__ == "__main__":
    main()