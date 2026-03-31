import asyncio
import base64
import json
import os
import threading

import requests
from ecdsa import NIST256p, SigningKey
from flow_py_sdk import flow_client
from flow_py_sdk.cadence import String, UFix64, Array, Address
from flow_py_sdk.tx import Tx, ProposalKey

from mock.constants import (
    FLOW_ENABLED, FLOW_REST_URL, FLOW_CONTRACT_ADDR, FLOW_CONTRACT_NAME,
    PAYMENT_PER_AUDITOR,
)
from mock.crypto import _EcdsaSigner
from mock.state import state

_flow_tx_lock = threading.Lock()


def _decode_cadence(v):
    if v is None:
        return None
    t = v.get("type") if isinstance(v, dict) else None
    if t in ("String",):
        return v["value"]
    if t in ("Fix64", "UFix64"):
        return float(v["value"])
    if t in ("Int", "UInt", "Int8", "UInt8", "Int16", "UInt16",
             "Int32", "UInt32", "Int64", "UInt64"):
        return int(v["value"])
    if t == "Bool":
        return v["value"]
    if t == "Array":
        return [_decode_cadence(i) for i in (v.get("value") or [])]
    if t == "Optional":
        return _decode_cadence(v["value"]) if v.get("value") is not None else None
    return v.get("value") if isinstance(v, dict) else v


async def _flow_tx_async(script, build_args_fn, label, wait_seal=False):
    flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "").removeprefix("0x")
    flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "").removeprefix("0x")
    if not flow_addr or not flow_key:
        print(f"[Flow] FLOW_ACCOUNT_ADDR/FLOW_ACCOUNT_KEY not set — {label} skipped")
        return None

    for attempt in range(3):
        try:
            async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                account      = await client.get_account(address=Address.from_hex(flow_addr))
                account_key  = account.keys[0]
                latest_block = await client.get_latest_block(is_sealed=True)
                tx = Tx(code=script)
                tx = build_args_fn(tx)
                tx = (tx
                    .with_reference_block_id(latest_block.id)
                    .with_gas_limit(9999)
                    .with_proposal_key(ProposalKey(
                        key_address         = Address.from_hex(flow_addr),
                        key_id              = account_key.index,
                        key_sequence_number = account_key.sequence_number,
                    ))
                    .with_payer(Address.from_hex(flow_addr))
                )
                tx.add_authorizers(Address.from_hex(flow_addr))
                sk     = SigningKey.from_string(bytes.fromhex(flow_key), curve=NIST256p)
                signer = _EcdsaSigner(sk)
                tx = tx.with_envelope_signature(
                    Address.from_hex(flow_addr),
                    account_key.index,
                    signer,
                )
                timeout = 60.0 if wait_seal else 30.0
                result  = await client.execute_transaction(tx, wait_for_seal=wait_seal, timeout=timeout)
                tx_id   = result.id.hex() if hasattr(result.id, "hex") else str(result.id)
                print(f"[Flow] ✓ {label} submitted → TX {tx_id}")
                print(f"[Flow]   https://testnet.flowscan.io/tx/{tx_id}")
                if wait_seal:
                    print(f"[Flow] ✓ {label} sealed")
                state.register_sealed.set()
                return tx_id
        except Exception as e:
            err = str(e)
            if "sequence number" in err and attempt < 2:
                print(f"[Flow] Sequence number mismatch on attempt {attempt + 1}, retrying...")
                await asyncio.sleep(2)
                continue
            if "already registered" in err:
                print(f"[Flow] {label} — already registered on-chain, skipping.")
                state.register_sealed.set()
                return None
            print(f"[Flow] {label} error: {e}")
            state.register_sealed.set()
            return None


def _register_transporter_on_flow():
    if not FLOW_ENABLED:
        print("[Flow] (simulated) registerNode for transporter")
        return
    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(nodeId: String, stake: UFix64) {\n"
        "    prepare(signer: auth(Storage) &Account) {}\n"
        "    execute {\n"
        "        SwarmVerifierV4.registerNode(nodeId: nodeId, stake: stake)\n"
        "    }\n"
        "}"
    )
    stake_ufix = int(10.0 * 1e8)

    def build(tx):
        tx = tx.add_arguments(String(state.pub_hex))
        tx = tx.add_arguments(UFix64(stake_ufix))
        return tx

    try:
        with _flow_tx_lock:
            asyncio.run(_flow_tx_async(cadence, build, "registerNode(transporter)", wait_seal=True))
    except Exception as e:
        if "already registered" not in str(e):
            print(f"[Flow] Transporter registerNode error: {e}")
        else:
            print("[Flow] Transporter already registered on-chain.")


def _register_anomaly_on_flow(quorum: dict):
    if not FLOW_ENABLED:
        print(f"[Flow] (simulated) registerAnomaly("
              f"submission_sig={state.current_event_id[:16]}...  "
              f"quorum={len(quorum)}  "
              f"conf={state.anomaly_confidence:.4f})")
        return

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(\n"
        "    transporterId: String, submissionSig: String,\n"
        "    anomalyConfidence: UFix64, quorumIds: [String], bidPrices: [UFix64]\n"
        ") {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute {\n"
        "        SwarmVerifierV4.registerAnomaly(\n"
        "            transporterId: transporterId,\n"
        "            submissionSig: submissionSig,\n"
        "            anomalyConfidence: anomalyConfidence,\n"
        "            quorumIds: quorumIds,\n"
        "            bidPrices: bidPrices\n"
        "        )\n"
        "    }\n"
        "}"
    )

    conf_ufix64     = int(state.anomaly_confidence * 1e8)
    quorum_ids      = list(quorum.keys())
    bid_prices_ufix = [int(PAYMENT_PER_AUDITOR * 1e8)] * len(quorum_ids)

    def build(tx):
        tx = tx.add_arguments(String(state.pub_hex))
        tx = tx.add_arguments(String(state.current_event_id))
        tx = tx.add_arguments(UFix64(conf_ufix64))
        tx = tx.add_arguments(Array([String(i) for i in quorum_ids]))
        tx = tx.add_arguments(Array([UFix64(p) for p in bid_prices_ufix]))
        return tx

    with _flow_tx_lock:
        asyncio.run(_flow_tx_async(cadence, build, "registerAnomaly", wait_seal=True))


def _submit_deposit_on_flow(event_id: str, auditor_pub_hex: str) -> bool:
    if not FLOW_ENABLED:
        print(f"[Flow] (simulated) recordDeposit(event_id={event_id[:16]}... auditor={auditor_pub_hex[:12]}...)")
        return True

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String, auditorId: String) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute {\n"
        "        SwarmVerifierV4.recordDeposit(eventId: eventId, auditorId: auditorId)\n"
        "    }\n"
        "}"
    )

    def build(tx):
        tx = tx.add_arguments(String(event_id))
        tx = tx.add_arguments(String(auditor_pub_hex))
        return tx

    try:
        with _flow_tx_lock:
            tx_id = asyncio.run(_flow_tx_async(cadence, build, "recordDeposit", wait_seal=True))
            return tx_id is not None
    except Exception as e:
        print(f"[Flow] recordDeposit error: {e}")
        return False


def _update_cid_on_flow(event_id: str, cid: str):
    if not FLOW_ENABLED:
        return

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String, cid: String) {\n"
        "    prepare(signer: &Account) {}\n"
        "    execute { SwarmVerifierV4.updateEventCid(eventId: eventId, cid: cid) }\n"
        "}"
    )

    def build(tx):
        tx = tx.add_arguments(String(event_id))
        tx = tx.add_arguments(String(cid))
        return tx

    try:
        with _flow_tx_lock:
            asyncio.run(_flow_tx_async(cadence, build, "updateEventCid", wait_seal=False))
    except Exception as e:
        print(f"[Flow] updateEventCid error: {e}")


def _finalize_event_on_flow(event_id: str):
    if not FLOW_ENABLED:
        return

    cadence = (
        f"import SwarmVerifierV4 from {FLOW_CONTRACT_ADDR}\n"
        "transaction(eventId: String) {\n"
        "    prepare(signer: auth(Storage) &Account) {}\n"
        "    execute { SwarmVerifierV4.finalizeEvent(eventId: eventId) }\n"
        "}"
    )

    def build(tx):
        return tx.add_arguments(String(event_id))

    with _flow_tx_lock:
        asyncio.run(_flow_tx_async(cadence, build, "finalizeEvent", wait_seal=True))


def _query_flow_stake_reputation(pubkey_hex: str) -> tuple:
    if not FLOW_ENABLED:
        return (0.0, 0.0)

    script = f"""
import {FLOW_CONTRACT_NAME} from {FLOW_CONTRACT_ADDR}
access(all) fun main(pubkey: String): [AnyStruct] {{
    let stake: UFix64? = {FLOW_CONTRACT_NAME}.getStake(nodeId: pubkey)
    let rep: Fix64?   = {FLOW_CONTRACT_NAME}.getReputation(nodeId: pubkey)
    let stakeVal: UFix64 = stake ?? 0.0
    let repVal: Fix64    = rep   ?? 0.0
    return [stakeVal, repVal]
}}
""".strip()

    encoded_script = base64.b64encode(script.encode()).decode()
    encoded_arg    = base64.b64encode(
        json.dumps({"type": "String", "value": pubkey_hex}).encode()
    ).decode()

    try:
        resp = requests.post(
            FLOW_REST_URL,
            json={"script": encoded_script, "arguments": [encoded_arg]},
            timeout=5,
        )
        if resp.status_code != 200:
            try:
                err = resp.json()
                print(f"[Flow] Script query failed {resp.status_code}: {err.get('message', resp.text[:120])}")
            except Exception:
                print(f"[Flow] Script query failed {resp.status_code}: {resp.text[:120]}")
            return (0.0, 0.0)

        raw_b64 = resp.json()
        if isinstance(raw_b64, dict):
            raw_b64 = raw_b64.get("value", "")
        decoded_bytes = base64.b64decode(raw_b64)
        cadence_val   = json.loads(decoded_bytes)
        values        = _decode_cadence(cadence_val)

        if not isinstance(values, list) or len(values) < 2:
            print(f"[Flow] Unexpected script result shape: {cadence_val!r}")
            return (0.0, 0.0)

        stake = float(values[0]) if values[0] is not None else 0.0
        rep   = float(values[1]) if values[1] is not None else 0.0
        return (stake, rep)

    except Exception as e:
        print(f"[Flow] Query error for {pubkey_hex[:12]}...: {e}")
        return (0.0, 0.0)