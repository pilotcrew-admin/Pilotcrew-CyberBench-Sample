#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from legacy_model import assess

MAX_ENVELOPE = 4 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthstarCompatibilityModel/1"

    def send_json(self, status: int, obj: dict) -> None:
        raw = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(200, {"status": "ready"})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/assess":
            return self.send_json(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_ENVELOPE:
                return self.send_json(413, {"error": "envelope_too_large"})
            envelope = json.loads(self.rfile.read(length).decode("utf-8"))
            result = assess(envelope)
        except Exception as exc:
            return self.send_json(400, {"error": "invalid_probe", "detail": str(exc)})
        self.send_json(200, result)

    def log_message(self, fmt: str, *args) -> None:
        print("northstar-model:", fmt % args, flush=True)


if __name__ == "__main__":
    print("Northstar compatibility model listening on 9090", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 9090), Handler).serve_forever()
