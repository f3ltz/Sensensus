import argparse
import os
import threading
import time
from dotenv import load_dotenv

load_dotenv()

from scripts.constants import DEPOSIT_AMOUNT, FLOW_API_URL_DEFAULT, FLOW_CONTRACT_ADDR_DEFAULT
from scripts.flow import register_on_flow
from scripts.state import state
from scripts.udp import broadcast_presence, listen

def main():
    parser = argparse.ArgumentParser(description="SwarmVerifier Auditor Node")
    parser.add_argument("--key-file",  default="../Identities/1.pem",
                        help="Path to PEM file for auditor identity.")
    parser.add_argument("--port", type=int, default=5011,
                        help="Unicast UDP port for this auditor.")
    parser.add_argument("--model",  default="./models/auditor_model.joblib",
                        help="Path ML model (Joblib).")
    parser.add_argument("--bid-price", type=float, default=1.0,
                        help="FLOW tokens to bid per verification job.")
    parser.add_argument("--deposit",   type=float, default=DEPOSIT_AMOUNT,
                        help="FLOW tokens locked as bond when unlocking CSV data.")
    parser.add_argument("--flow-url",  default=os.environ.get("FLOW_API_URL", FLOW_API_URL_DEFAULT),
                        help="Base URL for verdict submission (mock transporter or live).")
    parser.add_argument("--flow-contract", default=os.environ.get("FLOW_CONTRACT_ADDR", FLOW_CONTRACT_ADDR_DEFAULT),
                        help="SwarmVerifierV4 contract address on Flow Testnet.")
    parser.add_argument("--flow-enabled", action="store_true", default=False,
                        help="Submit verdicts to the live Flow contract.")
    args = parser.parse_args()

    if args.flow_enabled:
        missing = [v for v in ("FLOW_ACCOUNT_ADDR", "FLOW_ACCOUNT_KEY") if not os.environ.get(v)]
        if missing:
            print(f"[WARN] --flow-enabled set but missing env vars: {missing}")
            print("[WARN] Verdict submissions will fall back to mock until these are set.")

    # Initialize the global state object
    state.initialize(
        key_path           = args.key_file,
        model_path         = args.model,
        port               = args.port,
        bid_price          = args.bid_price,
        deposit            = args.deposit,
        flow_api_url       = args.flow_url,
        flow_contract_addr = args.flow_contract,
        flow_enabled       = args.flow_enabled,
    )

    print(f"[*] Auditor ready. pubkey={state.pub_hex[12:]}...")
    print(f"[*] Bid price:   {state.bid_price} FLOW")
    print(f"[*] Deposit:     {state.deposit_amount} FLOW")
    print(f"[*] Flow submit: {'ENABLED → testnet' if state.flow_enabled else 'DISABLED (mock /verdict)'}")

    if state.flow_enabled:
        register_on_flow()

    threading.Thread(target=broadcast_presence, daemon=True, name="beacon").start()
    threading.Thread(target=listen, daemon=True, name="listener").start()

    print("[*] Auditor running. Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")

if __name__ == "__main__":
    main()