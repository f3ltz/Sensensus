import secrets
import threading
import time

from mock.constants import ALPHA, BETA, ANOMALY_THRESHOLD, FLOW_ENABLED
from mock.flow import _finalize_event_on_flow, _update_cid_on_flow
from mock.state import state

# ── Consensus & Settlement Logic ──────────────────────────────────────────────

def _finalize_event():
    """
    Computes final CSwarm consensus, identifies true/false positives, issues slashing 
    or rewards formulas, and simulates Storacha upload to record evidence CID.
    """
    saved_event_id = state.current_event_id
    with state.verdicts_lock:
        received = dict(state.verdicts)

    quorum_ids = list(state.quorum.keys())
    n          = len(quorum_ids)

    if n == 0:
        return

    all_verdicts = {}
    for pub in quorum_ids:
        if pub in received:
            all_verdicts[pub] = received[pub]
        else:
            all_verdicts[pub] = {
                "verdict":    False,
                "confidence": 0.0,
                "ip":         state.quorum.get(pub, "?"),
                "silent":     True,
            }

    confidences       = [v["confidence"] for v in all_verdicts.values()]
    drop_votes        = sum(1 for v in all_verdicts.values() if v["verdict"])
    cswarm            = sum(confidences) / n
    consensus_verdict = drop_votes > (n // 2)

    auditor_results = []
    for pub in quorum_ids:
        v       = all_verdicts[pub]
        aligned = (v["verdict"] == consensus_verdict) and not v.get("silent", False)
        delta   = ALPHA * (cswarm - v["confidence"]) - (BETA if not aligned else 0.0)
        auditor_results.append({
            "pubkey_hex": pub,
            "ip":         v.get("ip", "?"),
            "verdict":    v["verdict"],
            "confidence": v["confidence"],
            "aligned":    aligned,
            "silent":     v.get("silent", False),
            "delta":      round(delta, 4),
        })

    with state.verdicts_lock:
        for r in auditor_results:
            if r["pubkey_hex"] in state.verdicts:
                state.verdicts[r["pubkey_hex"]]["aligned"] = r["aligned"]

    transporter_claimed_drop = state.anomaly_confidence >= ANOMALY_THRESHOLD
    transporter_slashed      = transporter_claimed_drop != consensus_verdict

    print("\n" + "═" * 64)
    print(f"  SETTLEMENT — event_id={saved_event_id[:16]}...")
    print("═" * 64)
    print(f"  Auditors     : {n}  (received: {len(received)}  silent: {n - len(received)})")
    print(f"  Drop votes   : {drop_votes}/{n}")
    print(f"  Cswarm       : {cswarm:.4f}")
    print(f"  Consensus    : {'DROP CONFIRMED' if consensus_verdict else 'NORMAL — false positive'}")
    print(f"  Transporter  : conf={state.anomaly_confidence:.4f}  claimed_drop={transporter_claimed_drop}  slashed={transporter_slashed}")
    print("─" * 64)
    for r in auditor_results:
        status  = "✓ aligned" if r["aligned"] else ("✗ silent" if r["silent"] else "✗ deviated")
        verdict = "DROP" if r["verdict"] else "NORM"
        print(f"  {r['pubkey_hex'][:12]}...  {verdict}  conf={r['confidence']:.4f}  ΔR={r['delta']:+.4f}  {status}")
    print("═" * 64)

    saved_event_id = state.current_event_id
    if FLOW_ENABLED and saved_event_id:
        print("[Flow] Calling finalizeEvent on-chain...")
        threading.Thread(target=_finalize_event_on_flow, args=(saved_event_id,), daemon=True).start()

    print("[Storacha] Simulating post-consensus bundle upload...")
    time.sleep(0.3)
    cid = "bafyrei" + secrets.token_hex(16)
    print(f"[Storacha] CID={cid}")

    if FLOW_ENABLED and saved_event_id:
        print("[Flow] Calling updateEventCid on-chain...")
        threading.Thread(target=_update_cid_on_flow, args=(saved_event_id, cid), daemon=True).start()
        flow_tx = "submitted"
    else:
        flow_tx = "0x" + secrets.token_hex(8)
        print(f"[Flow] (simulated) updateEventCid → tx={flow_tx}")

    print("═" * 64 + "\n")

    event = {
        "event_id":            state.current_event_id,
        "timestamp":           time.time(),
        "anomaly_confidence":  state.anomaly_confidence,
        "cswarm":              round(cswarm, 4),
        "consensus_verdict":   consensus_verdict,
        "drop_votes":          drop_votes,
        "total_auditors":      n,
        "transporter_slashed": transporter_slashed,
        "auditor_results":     auditor_results,
        "storacha_cid":        cid,
        "flow_tx":             flow_tx,
    }
    with state.events_lock:
        state.settled_events.insert(0, event)
        state.settled_events = state.settled_events[:20]

    state.system_status = "IDLE"