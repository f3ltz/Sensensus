import asyncio
import os
from ecdsa import NIST256p, SigningKey
from flow_py_sdk import flow_client
from flow_py_sdk.cadence import String, UFix64, Bool, Address
from flow_py_sdk.tx import Tx, ProposalKey

from scripts.constants import _REGISTER_NODE_SCRIPT, _SUBMIT_VERDICT_SCRIPT, VERDICT_WAIT_S
from scripts.crypto import _EcdsaSigner
from scripts.state import state

def register_on_flow():
    flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "")
    flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "")
    if not flow_addr or not flow_key:
        print("[Flow] Cannot registerNode — FLOW_ACCOUNT_ADDR/KEY not set.")
        return
    asyncio.run(_register_on_flow_async(flow_addr.removeprefix("0x"), flow_key.removeprefix("0x")))

async def _register_on_flow_async(flow_addr: str, flow_key: str):
    script = _REGISTER_NODE_SCRIPT.format(contract_addr=state.flow_contract_addr)
    sk     = SigningKey.from_string(bytes.fromhex(flow_key), curve=NIST256p)
    signer = _EcdsaSigner(sk)
    addr   = Address.from_hex(flow_addr)

    for attempt in range(3):
        try:
            async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                account      = await client.get_account(address=addr)
                account_key  = account.keys[0]
                latest_block = await client.get_latest_block(is_sealed=True)

                tx = (
                    Tx(code=script)
                    .add_arguments(String(state.pub_hex))
                    .add_arguments(UFix64(int(10.0 * 1e8)))   # 10 FLOW stake
                    .with_reference_block_id(latest_block.id)
                    .with_gas_limit(999)
                    .with_proposal_key(ProposalKey(
                        key_address         = addr,
                        key_id              = account_key.index,
                        key_sequence_number = account_key.sequence_number,
                    ))
                    .with_payer(addr)
                    .add_authorizers(addr)
                    .with_envelope_signature(addr, account_key.index, signer)
                )

                result = await client.execute_transaction(tx, wait_for_seal=True, timeout=60.0)
                tx_id = result.id.hex() if hasattr(result, 'id') else "unknown"
                print(f"[Flow] ✓ registerNode sealed — https://testnet.flowscan.io/tx/{tx_id}")
                return

        except Exception as e:
            err = str(e)
            if "already registered" in err.lower():
                print("[Flow] Auditor already registered on-chain — skipping.")
                return
            if "sequence number" in err and attempt < 2:
                print(f"[Flow] Seq mismatch (attempt {attempt+1}) — retrying in 3s...")
                await asyncio.sleep(3)
                continue
            print(f"[Flow] registerNode error: {e}")
            return

def submit_to_flow(body: dict):
    asyncio.run(_submit_to_flow_async(body))

async def _submit_to_flow_async(body: dict):
    flow_addr = os.environ.get("FLOW_ACCOUNT_ADDR", "")
    flow_key  = os.environ.get("FLOW_ACCOUNT_KEY",  "")

    if not flow_addr or not flow_key:
        print("[Flow] FLOW_ACCOUNT_ADDR or KEY not set — falling back to mock.")
        from scripts.verification import submit_to_mock
        submit_to_mock(body)
        return

    script = _SUBMIT_VERDICT_SCRIPT.format(contract_addr=state.flow_contract_addr)
    confidence_ufix64 = int(round(body["verdict_confidence"] * 1e8))
    sk = SigningKey.from_string(bytes.fromhex(flow_key.removeprefix("0x")), curve=NIST256p)
    signer = _EcdsaSigner(sk)
    addr = Address.from_hex(flow_addr)

    for attempt in range(3):
        try:
            async with flow_client(host="access.devnet.nodes.onflow.org", port=9000) as client:
                account      = await client.get_account(address=addr)
                account_key  = account.keys[0]
                latest_block = await client.get_latest_block(is_sealed=True)

                tx = (
                    Tx(code=script)
                    .add_arguments(String(body["event_id"]))
                    .add_arguments(String(body["auditor_pubkey"]))
                    .add_arguments(Bool(body["verdict"]))
                    .add_arguments(UFix64(confidence_ufix64))
                    .add_arguments(String(body["payload_signature"]))
                    .add_arguments(String(body["verdict_signature"]))
                    .with_reference_block_id(latest_block.id)
                    .with_gas_limit(999)
                    .with_proposal_key(ProposalKey(
                        key_address         = addr,
                        key_id              = account_key.index,
                        key_sequence_number = account_key.sequence_number,
                    ))
                    .with_payer(addr)
                    .add_authorizers(addr)
                    .with_envelope_signature(addr, account_key.index, signer)
                )

                result = await client.execute_transaction(tx, wait_for_seal=True, timeout=float(VERDICT_WAIT_S))
                tx_id = result.id.hex() if hasattr(result, 'id') else "unknown"
                print(f"[Flow] ✓ submitVerdict sealed — https://testnet.flowscan.io/tx/{tx_id}")
                return

        except Exception as e:
            err = str(e)
            if "sequence number" in err and attempt < 2:
                print(f"[Flow] Seq number mismatch (attempt {attempt+1}) — retrying in 3s...")
                await asyncio.sleep(3)
                continue
            print(f"[Flow] submitVerdict error: {e}")
            return