import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from mock.crypto import _verify
from mock.flow import _submit_deposit_on_flow
from mock.settlement import _finalize_event
from mock.state import state


class TransporterHTTP(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def do_GET(self):
        parsed    = urlparse(self.path)
        client_ip = self.client_address[0]

        if parsed.path == "/state":
            self._handle_state()
            return
        if parsed.path == "/data":
            params     = parse_qs(parsed.query)
            pubkey_hex = params.get("pubkey", [None])[0]
            self._handle_data(pubkey_hex, client_ip)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if self.path == "/pay":
            self._handle_pay(body)
        elif self.path == "/verdict":
            self._handle_verdict(body)
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_state(self):
        with state.registry_lock:
            registry = {
                pub: {
                    "ip":        info["ip"],
                    "last_seen": info["last_seen"],
                    "active":    (time.time() - info["last_seen"]) < 15,
                }
                for pub, info in state.registry.items()
            }

        with state.bids_lock:
            quorum = list(state.quorum.keys())

        with state.verdicts_lock:
            verdicts = {
                pub: {
                    "verdict":    v["verdict"],
                    "confidence": v["confidence"],
                    "ip":         v["ip"],
                    "aligned":    v.get("aligned"),
                }
                for pub, v in state.verdicts.items()
            }

        with state.events_lock:
            events = list(state.settled_events)

        self._send_json(200, {
            "transporter_pubkey":  state.pub_hex,
            "system_status":       state.system_status,
            "anomaly_confidence":  state.anomaly_confidence,
            "current_event_id":    state.current_event_id,
            "registry":            registry,
            "quorum":              quorum,
            "verdicts":            verdicts,
            "last_quat":           state.last_quat,
            "settled_events":      events,
            "ts":                  time.time(),
        })

    def _handle_data(self, pubkey_hex, client_ip):
        if not pubkey_hex or len(pubkey_hex) != 128:
            self._send_json(400, {"error": "missing or invalid ?pubkey query param"})
            return

        if not state.quorum:
            self._send_json(403, {"error": "no active quorum"})
            return

        if pubkey_hex not in state.quorum:
            print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... → 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        nonce = secrets.token_bytes(16)
        with state.nonces_lock:
            state.nonces[pubkey_hex] = nonce

        print(f"[HTTP] GET /data {client_ip} pubkey={pubkey_hex[:12]}... → 402 nonce={nonce.hex()[:12]}...")
        self._send_json(402, {
            "status":      "payment_required",
            "endpoint":    "/pay",
            "nonce":       nonce.hex(),
            "description": "Sign the nonce with your private key to receive IMU data",
        })

    def _handle_pay(self, body: dict):
        client_ip  = self.client_address[0]
        pubkey_hex = body.get("pubkey", "")
        sig_hex    = body.get("signature", "")

        if len(pubkey_hex) != 128 or len(sig_hex) != 128:
            self._send_json(400, {"error": "pubkey and signature must be 128 hex chars each"})
            return

        with state.nonces_lock:
            nonce = state.nonces.get(pubkey_hex)

        if not nonce:
            self._send_json(403, {"error": "no pending nonce for this pubkey — call GET /data first"})
            return

        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(nonce, sig_bytes, pub_bytes):
            print(f"[HTTP] POST /pay {client_ip} → 403 bad signature")
            self._send_json(403, {"error": "signature verification failed"})
            return

        if pubkey_hex not in state.quorum:
            print(f"[HTTP] POST /pay {client_ip} → 403 not in quorum")
            self._send_json(403, {"error": "pubkey not in quorum"})
            return

        if not state.register_sealed.wait(timeout=55):
            print(f"[HTTP] POST /pay {client_ip} → 503 registerAnomaly seal timeout")
            self._send_json(503, {"error": "chain not ready — try again"})
            return

        with state.nonces_lock:
            state.nonces.pop(pubkey_hex, None)

        if not _submit_deposit_on_flow(state.current_event_id, pubkey_hex):
            print(f"[HTTP] POST /pay {client_ip} → 503 recordDeposit failed")
            self._send_json(503, {"error": "Flow.recordDeposit() failed — deposit not locked on-chain"})
            return

        print(f"[HTTP] POST /pay {client_ip} pubkey={pubkey_hex[:12]}... → 200 OK")
        payload = state.build_payload_json(pubkey_hex)
        self._send_json(200, {
            "csv":     state.csv_data,
            "payload": payload,
        })

    def _handle_verdict(self, body: dict):
        client_ip = self.client_address[0]

        event_id        = body.get("event_id",           "")
        auditor_pub     = body.get("auditor_pubkey",     "")
        verdict         = body.get("verdict")
        confidence      = body.get("verdict_confidence")
        payload_sig_hex = body.get("payload_signature",  "")
        verdict_sig_hex = body.get("verdict_signature",  "")
        csv_cid         = body.get("csv_cid",            "")

        missing = [f for f, v in [
            ("event_id",           event_id),
            ("auditor_pubkey",     auditor_pub),
            ("verdict",            verdict),
            ("verdict_confidence", confidence),
            ("payload_signature",  payload_sig_hex),
            ("verdict_signature",  verdict_sig_hex),
        ] if v is None or v == ""]
        if missing:
            self._send_json(400, {"error": f"missing fields: {missing}"})
            return

        if event_id != state.current_event_id:
            print(f"[Verdict] {client_ip} event_id mismatch: got {event_id[:16]}... "
                  f"expected {state.current_event_id[:16]}...")
            self._send_json(409, {"error": "event_id does not match active event"})
            return

        if auditor_pub not in state.quorum:
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 not in quorum")
            self._send_json(403, {"error": "not in quorum"})
            return

        with state.verdicts_lock:
            if auditor_pub in state.verdicts:
                self._send_json(409, {"error": "verdict already received from this auditor"})
                return

        with state.issued_payload_sigs_lock:
            expected_payload_sig = state.issued_payload_sigs.get(auditor_pub, "")
        if payload_sig_hex != expected_payload_sig:
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 payload_sig mismatch")
            self._send_json(403, {"error": "payload_signature does not match issued value"})
            return

        canonical = f"{auditor_pub}:{int(verdict)}:{float(confidence):.4f}".encode()
        try:
            pub_bytes = bytes.fromhex(auditor_pub)
            sig_bytes = bytes.fromhex(verdict_sig_hex)
        except ValueError:
            self._send_json(400, {"error": "hex decode failed"})
            return

        if not _verify(canonical, sig_bytes, pub_bytes):
            print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → 403 bad verdict sig")
            self._send_json(403, {"error": "verdict signature verification failed"})
            return

        with state.verdicts_lock:
            state.verdicts[auditor_pub] = {
                "verdict":           bool(verdict),
                "confidence":        float(confidence),
                "payload_signature": payload_sig_hex,
                "verdict_signature": verdict_sig_hex,
                "csv_cid":           csv_cid,
                "ip":                client_ip,
            }
            count = len(state.verdicts)

        label = "DROP" if verdict else "NORMAL"
        print(f"[Verdict] {client_ip} pubkey={auditor_pub[:12]}... → {label} "
              f"conf={float(confidence):.4f} ({count}/{state.expected_verdicts})")
        self._send_json(200, {"status": "received"})

        if count >= state.expected_verdicts:
            threading.Thread(target=_finalize_event, daemon=True).start()