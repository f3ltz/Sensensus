from dotenv import load_dotenv

load_dotenv()

MULTICAST_GROUP    = "239.0.0.1"
MULTICAST_PORT     = 5005
BID_PORT           = 5006
HTTP_PORT          = 8080

CSV_BUFFER_SAMPLES = 75
WINDOW_SIZE        = 50

BID_WINDOW_S      = 0.6
VERDICT_TIMEOUT_S = 55.0

W_PRICE     = 0.5
W_REP       = 0.3
W_STAKE     = 0.2
QUORUM_SIZE = 3

ALPHA = 10.0
BETA  = 5.0

ANOMALY_THRESHOLD = 0.85

FLOW_ENABLED        = True
FLOW_REST_URL       = "https://rest-testnet.onflow.org/v1/scripts"
FLOW_CONTRACT_ADDR  = "0xfcd23c8d1553708a"
FLOW_CONTRACT_NAME  = "SwarmVerifierV4"
PAYMENT_PER_AUDITOR = 0.001