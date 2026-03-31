import io
import requests
import numpy as np
import pandas as pd

from scripts.constants import CSV_COLUMNS, FEATURE_COLS, WINDOW_SIZE, INPUT_TENSOR_SIZE
from scripts.crypto import verdict_canonical, sign_data

from scripts.state import state


def run_verification(csv_raw: str, payload_signature: str):
    if state.model is None:
        print("[ML] No model loaded — submitting fallback verdict (False, 0.5).")
        submit_verdict(False, 0.5, payload_signature)
        return

    try:
        df = pd.read_csv(io.StringIO(csv_raw), names=CSV_COLUMNS, header=0)

        missing = [c for c in FEATURE_COLS if c not in df.columns]
        if missing:
            print(f"[ML] CSV missing columns: {missing}. Aborting.")
            return

        data_window = df[FEATURE_COLS].values
        if len(data_window) >= WINDOW_SIZE:
            data_window = data_window[-WINDOW_SIZE:]
        else:
            pad = np.zeros((WINDOW_SIZE - len(data_window), len(FEATURE_COLS)))
            data_window = np.vstack((pad, data_window))

        X = data_window.flatten().reshape(1, -1)
        if X.shape[1] != INPUT_TENSOR_SIZE:
            print(f"[ML] Shape mismatch. Aborting.")
            return

        prediction    = state.model.predict(X)[0]
        probabilities = state.model.predict_proba(X)[0]
        confidence    = float(max(probabilities))
        verdict_bool  = bool(prediction == 1)

        print(f"[ML] Verdict: {'DROP' if verdict_bool else 'NORMAL'} | confidence={confidence:.4f}")
        submit_verdict(verdict_bool, confidence, payload_signature)

    except Exception as e:
        print(f"[ML] Error: {e}")

def submit_verdict(verdict_bool: bool, confidence: float, payload_signature: str):
    with state.state_lock:
        event_id = state.current_event_id

    if not event_id:
        print("[Verdict] No event_id available — aborting.")
        return

    canonical = verdict_canonical(state.pub_hex, verdict_bool, confidence)
    sig_hex   = sign_data(state.sk, canonical).hex()

    body = {
        "event_id":           event_id,
        "auditor_pubkey":     state.pub_hex,
        "verdict":            verdict_bool,
        "verdict_confidence": confidence,
        "payload_signature":  payload_signature,
        "verdict_signature":  sig_hex,
        "csv_cid":            "", 
    }

    if state.flow_enabled:
        from scripts.flow import submit_to_flow
        submit_to_flow(body)
    else:
        submit_to_mock(body)

def submit_to_mock(body: dict):
    url = f"{state.flow_api_url}/verdict"
    try:
        r = requests.post(url, json=body, timeout=10)
        if r.status_code == 200:
            print(f"[Mock] ✓ Verdict submitted to mock transporter.")
        else:
            print(f"[Mock] Verdict rejected: HTTP {r.status_code} — {r.text[:120]}")
    except Exception as e:
        print(f"[Mock] Network error: {e}")