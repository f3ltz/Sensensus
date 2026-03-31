import socket
import struct
import time

from mock.constants import MULTICAST_GROUP, MULTICAST_PORT, BID_PORT
from mock.crypto import _verify
from mock.state import state

# ── UDP Networking (Beacons & Bids) ───────────────────────────────────────────

def multicast_listener():
    """Listens for PKT_BEACON to build the registry of available auditors."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(('', MULTICAST_PORT))
    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    print(f"[UDP] Multicast listener on {MULTICAST_GROUP}:{MULTICAST_PORT}")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 129 and data[0] == 0x01:
            _handle_beacon(data, addr)


def bid_listener():
    """Listens for PKT_BID from auditors responding to anomalies."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', BID_PORT))
    print(f"[UDP] Bid listener on 0.0.0.0:{BID_PORT}")

    while True:
        data, addr = sock.recvfrom(1024)
        if len(data) == 137 and data[0] == 0x02:
            _handle_bid(data, addr)


def _handle_beacon(data: bytes, addr):
    pub_bytes     = data[1:65]
    sig           = data[65:129]
    signed_region = data[0:65]

    if not _verify(signed_region, sig, pub_bytes):
        print(f"[UDP] Beacon from {addr[0]} — bad signature, dropping")
        return

    pub_hex = pub_bytes.hex()
    with state.registry_lock:
        is_new = pub_hex not in state.registry
        state.registry[pub_hex] = {"ip": addr[0], "last_seen": time.time()}

    if is_new:
        print(f"[UDP] ✓ Registered  {addr[0]}  pubkey={pub_hex[:12]}...")
    else:
        print(f"[UDP] ↻ Refreshed   {addr[0]}  pubkey={pub_hex[:12]}...")


def _handle_bid(data: bytes, addr):
    if not state.collecting_bids:
        return

    pub_bytes     = data[1:65]
    price_bytes   = data[65:73]
    sig           = data[73:137]
    signed_region = data[0:73]

    if not _verify(signed_region, sig, pub_bytes):
        print(f"[UDP] Bid from {addr[0]} — bad signature, dropping")
        return

    pub_hex = pub_bytes.hex()
    price   = struct.unpack('<d', price_bytes)[0]

    with state.registry_lock:
        if pub_hex not in state.registry:
            print(f"[UDP] Bid from unregistered pubkey {pub_hex[:12]}... — dropping")
            return

    with state.bids_lock:
        if pub_hex in state.bids:
            return
        state.bids[pub_hex] = {"ip": addr[0], "price": price}

    print(f"[UDP] ✓ Bid from {addr[0]}  pubkey={pub_hex[:12]}...  price={price:.4f} FLOW")


def _send_quorum_notifications(quorum: dict):
    """Broadcasts PKT_QUORUM to alert selected auditors."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    for pub_hex, ip in quorum.items():
        try:
            pub_bytes = bytes.fromhex(pub_hex)
        except ValueError:
            print(f"[Quorum] Cannot decode pubkey for {ip} — skipping")
            continue
        packet = state.build_quorum_packet(pub_bytes)
        sock.sendto(packet, (MULTICAST_GROUP, MULTICAST_PORT))
        print(f"[Quorum] Sent PKT_QUORUM → multicast (for pubkey={pub_hex[:12]}...)")
    sock.close()