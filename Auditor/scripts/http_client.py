import requests
from scripts.constants import HTTP_PORT, DELIVERY_WAIT_S
from scripts.crypto import sign_data
from scripts.verification import run_verification
from scripts.state import state

def execute_x402_fetch(transporter_ip: str):
    base_url = f"http://{transporter_ip}:{HTTP_PORT}"

    try:
        # ── Step 1: GET /data ─────────────────────────────────────────────
        resp = requests.get(
            f"{base_url}/data",
            params={"pubkey": state.pub_hex},
            timeout=DELIVERY_WAIT_S,
        )

        if resp.status_code == 403:
            print(f"[x402] 403 — Standing down.")
            return

        if resp.status_code != 402:
            print(f"[x402] Unexpected status on GET /data: {resp.status_code}. Aborting.")
            return

        nonce_hex = resp.json().get("nonce", "")
        if not nonce_hex:
            print("[x402] 402 missing nonce. Aborting.")
            return
        print(f"[x402] 402 received. nonce={nonce_hex[:16]}...")

        # ── Step 2: POST /pay ─────────────────────────────────────────────
        nonce_bytes = bytes.fromhex(nonce_hex)
        sig_hex     = sign_data(state.sk, nonce_bytes).hex()

        pay_resp = requests.post(
            f"{base_url}/pay",
            json={
                "pubkey":    state.pub_hex,
                "signature": sig_hex,
                "deposit":   state.deposit_amount,
            },
            timeout=DELIVERY_WAIT_S,
        )

        if pay_resp.status_code == 503:
            print("[x402] 503 — transporter Flow.submitDeposit() failed.")
            return

        if pay_resp.status_code != 200:
            print(f"[x402] POST /pay rejected: {pay_resp.status_code}. Aborting.")
            return

        body    = pay_resp.json()
        csv_raw = body.get("csv", "")
        payload = body.get("payload", {})

        if not csv_raw or not payload:
            print("[x402] 200 missing csv or payload. Aborting.")
            return

        event_id = payload.get("event_id", "")
        payload_sig = payload.get("payload_signature", "")
        if not event_id or not payload_sig:
            print("[x402] payload missing identifiers — verdict chain broken. Aborting.")
            return

        print(f"[x402] ✓ Data access granted. eventId={event_id[:16]}...")

        with state.state_lock:
            state.current_event_id = event_id

        run_verification(csv_raw, payload_sig)

    except requests.exceptions.ConnectionError as e:
        print(f"[x402] Connection error: {e}")
    except requests.exceptions.Timeout:
        print(f"[x402] Timeout after {DELIVERY_WAIT_S}s")
    except Exception as e:
        print(f"[x402] Unexpected error: {e}")