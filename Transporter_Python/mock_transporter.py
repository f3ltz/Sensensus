import threading
import time
from http.server import HTTPServer
from dotenv import load_dotenv

load_dotenv()

from mock.anomaly import trigger_anomaly
from mock.constants import HTTP_PORT
from mock.flow import _register_transporter_on_flow
from mock.transporter_http import TransporterHTTP
from mock.state import state
from mock.udp import bid_listener, multicast_listener

# ── Entry Point (CLI & Services) ──────────────────────────────────────────────

def cli():
    """Interactive command-line interface to trigger flows manually."""
    print("\nMock Transporter ready.")
    print("Commands:  [a] trigger anomaly    [r] show registry    [q] quit\n")
    while True:
        try:
            cmd = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if cmd == "a":
            with state.registry_lock:
                n = len(state.registry)
            if n == 0:
                print("[!] No auditors registered yet. Wait for a beacon.")
            elif state.system_status != "IDLE":
                print(f"[!] Busy ({state.system_status}) — wait for current cycle to finish.")
            else:
                threading.Thread(target=trigger_anomaly, daemon=True).start()

        elif cmd == "r":
            with state.registry_lock:
                if not state.registry:
                    print("  No auditors registered.")
                for pub, info in state.registry.items():
                    age = time.time() - info["last_seen"]
                    print(f"  {info['ip']}  pubkey={pub[:12]}...  last_seen={age:.0f}s ago")

        elif cmd == "q":
            print("Exiting.")
            break

        else:
            print("  Unknown command.")

if __name__ == "__main__":
    # Boot sequence: Flow blockchain -> UDP networking -> HTTP endpoints -> Interactive CLI
    _register_transporter_on_flow()
    
    threading.Thread(target=multicast_listener, daemon=True).start()
    threading.Thread(target=bid_listener,       daemon=True).start()

    server = HTTPServer(("0.0.0.0", HTTP_PORT), TransporterHTTP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[HTTP] Server on 0.0.0.0:{HTTP_PORT}")

    cli()