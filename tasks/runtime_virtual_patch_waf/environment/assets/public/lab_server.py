#!/usr/bin/env python3
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from legacy_client import LegacyLabError, assess_legacy, redact_assessment
from waf_runtime import evaluate_policy, load_policy

POLICY = Path("/app/edge-policy.json")

class Handler(BaseHTTPRequestHandler):
    server_version = "NorthstarLab/1"

    def _send(self, status, obj):
        raw = (json.dumps(obj, ensure_ascii=False) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        if self.path == "/__lab/health":
            return self._send(200, {"service": "northstar-compatibility-lab", "status": "ready", "policy_present": POLICY.exists()})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "invalid_content_length"})
        if length < 0 or length > 2097152:
            return self._send(413, {"error": "lab_request_limit"})
        body = self.rfile.read(length)
        request = {
            "method": self.command,
            "target": self.path,
            "headers": list(self.headers.items()),
            "body_b64": __import__("base64").b64encode(body).decode(),
        }
        if POLICY.exists():
            policy, errors = load_policy(POLICY)
            if errors:
                return self._send(503, {"error": "policy_invalid", "details": errors[:10]})
            edge = evaluate_policy(policy, request)
            if edge["decision"] != "allow":
                return self._send(edge["status"], {"edge_decision": edge["decision"], "audit": edge.get("audit")})
        try:
            result = assess_legacy(request)
        except LegacyLabError as exc:
            return self._send(502, {"error": "legacy_lab_unavailable", "detail": str(exc)})
        status = 400 if result["outcome"] in {"malformed", "application_validation_error"} else 200
        return self._send(status, {"edge_decision": "allow", "legacy": redact_assessment(result)})

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle

    def log_message(self, fmt, *args):
        print("northstar-lab:", fmt % args, flush=True)

if __name__ == "__main__":
    print("Northstar compatibility lab listening on 127.0.0.1:8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
