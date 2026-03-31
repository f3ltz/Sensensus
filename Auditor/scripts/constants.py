# ── Column names (must match Pico's imu_buildCsvBuffer()) ────────────────────
CSV_COLUMNS  = ['timestamp_ms', 'ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']
FEATURE_COLS = ['ax', 'ay', 'az', 'qw', 'qx', 'qy', 'qz']

# ── Sizes (must match config.h) ───────────────────────────────────────────────
CSV_BUFFER_SAMPLES = 75    # rows the Pico serves
WINDOW_SIZE        = 50    # rows fed to Random Forest (last 50)
INPUT_TENSOR_SIZE  = 350   # 50 × 7

# ── Network constants (must match config.h) ───────────────────────────────────
MULTICAST_GROUP = '239.0.0.1'
MULTICAST_PORT  = 5005
BID_PORT        = 5006
HTTP_PORT       = 8080

# ── Timing ────────────────────────────────────────────────────────────────────
BEACON_INTERVAL_S = 5.0
QUORUM_WAIT_S     = 120.0   # wait for PKT_QUORUM after sending a bid
DELIVERY_WAIT_S   = 90.0    # x402 HTTP timeout (generous — submitDeposit blocks Pico)
VERDICT_WAIT_S    = 90.0    # Flow TX timeout

# ── Economics ────────────────────────────────────────────────────────────────
DEPOSIT_AMOUNT = 0.5        # FLOW locked as bond at POST /pay

# ── Flow defaults (override via CLI args or env vars) ────────────────────────
FLOW_API_URL_DEFAULT       = "http://localhost:8080"    # mock_transporter
FLOW_CONTRACT_ADDR_DEFAULT = "0xfcd23c8d1553708a"       # testnet placeholder

# ── Cadence scripts ───────────────────────────────────────────────────────────
_REGISTER_NODE_SCRIPT = """
import SwarmVerifierV4 from {contract_addr}
transaction(nodeId: String, stake: UFix64) {{
    prepare(signer: &Account) {{}}
    execute {{
        SwarmVerifierV4.registerNode(nodeId: nodeId, stake: stake)
    }}
}}
"""

_SUBMIT_VERDICT_SCRIPT = """
import SwarmVerifierV4 from {contract_addr}
transaction(
    eventId: String, auditorId: String, verdict: Bool,
    confidence: UFix64, payloadSignature: String, verdictSignature: String
) {{
    prepare(signer: &Account) {{}}
    execute {{
        SwarmVerifierV4.submitVerdict(
            eventId: eventId, auditorId: auditorId, verdict: verdict,
            confidence: confidence, payloadSignature: payloadSignature,
            verdictSignature: verdictSignature
        )
    }}
}}
"""