"""Minimal JSON HTTP API (standard library only)."""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger(__name__)


def make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ix500-netscan"

        def log_message(self, fmt, *args):
            log.debug("api: " + fmt, *args)

        def _json(self, code: int, payload) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if path == "/health":
                ok = service.healthy()
                return self._json(200 if ok else 503, {"ok": ok})
            if path == "/api/status":
                return self._json(200, service.status())
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = self.path.split("?", 1)[0].rstrip("/")
            if path != "/api/mode":
                return self._json(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 1024:
                    raise ValueError("body too large")
                mode = json.loads(self.rfile.read(length) or b"{}").get("mode")
                service.set_mode(mode)
            except (ValueError, AttributeError) as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"mode": service.mode})

    return Handler


def start(service, bind: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((bind, port), make_handler(service))
    threading.Thread(target=httpd.serve_forever, daemon=True, name="api").start()
    log.info("API on http://%s:%d", bind, port)
    return httpd
