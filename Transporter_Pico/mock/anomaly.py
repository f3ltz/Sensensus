import socket
import threading
import time

import numpy as np

from mock.constants import (
    MULTICAST_GROUP, MULTICAST_PORT, BID_WINDOW_S, VERDICT_TIMEOUT_S, FLOW_ENABLED,
)
from mock.flow import _register_anomaly_on_flow, _finalize_event_on_flow
from mock.imu import _generate_drop_csv
from mock.quorum import _select_quorum
from mock.settlement import _finalize_event
from mock.state import state
from mock.udp import _send_quorum_notifications


def trigger_anomaly():
    state.csv_data           = _generate_drop_csv()
    state.anomaly_confidence = round(float(np.random.uniform(0.87, 0.99)), 4)

    try:
        last_row = state.csv_data.strip().split("\n")[-1].split(",")
        state.last_quat = {
            "qw": float(last_row[4]), "qx": float(last_row[5]),
            "qy": float(last_row[6]), "qz": float(last_row[7]),
        }
    except Exception:
        pass

    with state.bids_lock:
        state.bids.clear()
    with state.verdicts_lock:
        state.verdicts.clear()
    with state.issued_payload_sigs_lock:
        state.issued_payload_sigs.clear()
    state.quorum.clear()
    state.current_event_id = ""
    state.collecting_bids  = True
    state.system_status    = "ANOMALY"
    state.register_sealed.clear()

    packet = state.build_anomaly_packet()
    sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
    sock.close()
    print(f"\n[Anomaly] Broadcast PKT_ANOMALY | confidence={state.anomaly_confidence:.4f}")
    print(f"[Anomaly] Collecting bids for {BID_WINDOW_S}s...")

    time.sleep(BID_WINDOW_S)
    state.collecting_bids = False

    with state.bids_lock:
        all_bids = dict(state.bids)

    if not all_bids:
        print("[Anomaly] No bids received — returning to IDLE\n")
        state.system_status = "IDLE"
        return

    quorum = _select_quorum(all_bids)

    if not quorum:
        print("[Anomaly] No eligible quorum members — returning to IDLE\n")
        state.system_status = "IDLE"
        return

    state.quorum            = quorum
    state.expected_verdicts = len(quorum)

    state.current_event_id = state.build_submission_sig(list(quorum.keys()))

    src = "Flow-ranked" if FLOW_ENABLED else "local (bid price only)"
    print(f"[Anomaly] Quorum ({src}): {len(quorum)} auditor(s)")
    for pub_hex, ip in quorum.items():
        bid = all_bids.get(pub_hex, {})
        print(f"           {ip}  pubkey={pub_hex[:12]}...  price={bid.get('price', '?'):.4f} FLOW")
    print(f"[Anomaly] submission_sig (event_id)={state.current_event_id[:24]}...")

    state.register_sealed.clear()

    register_thread = threading.Thread(
        target=_register_anomaly_on_flow, args=(quorum,), daemon=True
    )
    register_thread.start()

    _send_quorum_notifications(quorum)

        # NEW
    state.system_status = "DELIVERING"
    print(f"[Anomaly] HTTP server armed. Waiting up to {VERDICT_TIMEOUT_S}s for verdicts...")

    if FLOW_ENABLED:
        saved_event_id = state.current_event_id

        print("[Flow] Waiting for registerAnomaly to seal before starting verdict window...")
        state.register_sealed.wait(timeout=60)

        print(f"[Flow] registerAnomaly sealed. Waiting {VERDICT_TIMEOUT_S}s verdict window...")
        deadline = time.time() + VERDICT_TIMEOUT_S

        while time.time() < deadline:
            with state.verdicts_lock:
                received = len(state.verdicts)
            if received >= state.expected_verdicts:
                print(f"[Flow] All {received} verdicts received early — proceeding to finalize")
                break
            time.sleep(1)
        else:
            with state.verdicts_lock:
                received = len(state.verdicts)
            print(f"[Flow] Verdict window elapsed — {received}/{state.expected_verdicts} received")

        print("[Flow] Waiting 20s for auditor txs to seal on-chain...")
        time.sleep(20)

        if saved_event_id:
            print("[Flow] Calling finalizeEvent on-chain...")
            state.system_status = "FINALIZING"
            _finalize_event_on_flow(saved_event_id)

        state.system_status = "IDLE"
    else:
        deadline = time.time() + VERDICT_TIMEOUT_S
        while time.time() < deadline:
            with state.verdicts_lock:
                if len(state.verdicts) >= state.expected_verdicts:
                    break
            time.sleep(0.5)
        else:
            with state.verdicts_lock:
                received = len(state.verdicts)
            print(f"[Anomaly] Verdict timeout — {received}/{state.expected_verdicts} received")
        _finalize_event()

    state.quorum.clear()
    with state.nonces_lock:
        state.nonces.clear()
    print("[Anomaly] Cycle complete, returning to IDLE\n")