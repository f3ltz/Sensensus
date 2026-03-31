import select
import socket
import struct
import threading
import time

from scripts.constants import MULTICAST_GROUP, MULTICAST_PORT, BID_PORT, BEACON_INTERVAL_S, QUORUM_WAIT_S
from scripts.crypto import sign_data, verify_signature
from scripts.http_client import execute_x402_fetch
from scripts.state import state

def broadcast_presence():
    header = bytes([0x01]) + state.pub_bytes
    sig    = sign_data(state.sk, header)
    packet = header + sig
    assert len(packet) == 129

    print(f"[Beacon] Broadcasting to {MULTICAST_GROUP}:{MULTICAST_PORT} every {BEACON_INTERVAL_S}s")
    while True:
        try:
            state.unicast_sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
        except Exception as e:
            print(f"[Beacon] Send error: {e}")
        time.sleep(BEACON_INTERVAL_S)

def listen():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.bind(('', MULTICAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f"[*] Listening on {MULTICAST_GROUP}:{MULTICAST_PORT}")

    while True:
        try:
            readable, _, _ = select.select([sock, state.unicast_sock], [], [])
            for s in readable:
                data, addr = s.recvfrom(1024)
                if not data: continue
                
                pkt_type = data[0]
                if pkt_type == 0x03 and len(data) == 133:
                    _handle_anomaly(data, addr)
                elif pkt_type == 0x04 and len(data) == 129:
                    _handle_quorum(data, addr)
        except Exception as e:
            print(f"[Listen] Error: {e}")

def _handle_anomaly(data: bytes, addr):
    transporter_pubkey = data[1:65]
    confidence         = struct.unpack('<f', data[65:69])[0]
    sig                = data[69:133]

    if not verify_signature(data[0:69], sig, transporter_pubkey):
        print(f"[WARN] Anomaly from {addr[0]} — bad sig. Dropping.")
        return

    print(f"\n[Anomaly] ✓ Verified | transporter={addr[0]} | confidence={confidence:.4f}")

    cycle_event = threading.Event()
    with state.state_lock:
        state.transporter_pubkey = bytes(transporter_pubkey)
        state.transporter_ip     = addr[0]
        state.current_event_id   = None
        state.quorum_event       = cycle_event

    _send_bid(addr[0])

    threading.Thread(
        target=_wait_for_quorum_then_fetch,
        args=(cycle_event,),
        daemon=True,
        name="quorum-wait",
    ).start()

def _send_bid(transporter_ip: str):
    header   = bytes([0x02]) + state.pub_bytes + struct.pack('<d', state.bid_price)
    sig      = sign_data(state.sk, header)
    packet   = header + sig
    assert len(packet) == 137

    try:
        for attempt in range(3):
            state.unicast_sock.sendto(packet, (transporter_ip, BID_PORT))
            time.sleep(0.3)
        print(f"[Bid] Sent {state.bid_price} FLOW bid to {transporter_ip}:{BID_PORT}")
    except Exception as e:
        print(f"[Bid] Send error: {e}")

def _wait_for_quorum_then_fetch(cycle_event: threading.Event):
    selected = cycle_event.wait(timeout=QUORUM_WAIT_S)
    if not selected:
        print(f"[Quorum] Not selected within {QUORUM_WAIT_S}s — standing down.")
        return

    with state.state_lock:
        transporter_ip = state.transporter_ip

    if not transporter_ip:
        print("[Quorum] No transporter IP stored — cannot proceed.")
        return

    execute_x402_fetch(transporter_ip)

def _handle_quorum(data: bytes, addr):
    nominated_pubkey = data[1:65]
    sig              = data[65:129]

    with state.state_lock:
        transporter_pubkey = state.transporter_pubkey
        cycle_event        = state.quorum_event

    if transporter_pubkey is None:
        return

    if not verify_signature(data[0:65], sig, transporter_pubkey):
        print(f"[WARN] PKT_QUORUM from {addr[0]} — bad sig. Ignoring.")
        return

    if nominated_pubkey != state.pub_bytes:
        return

    print(f"[Quorum] ✓ Selected! Proceeding to x402 fetch.")
    cycle_event.set()