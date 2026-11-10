"""User-space scan daemon with a loopback-only local API.

Capability statement (permanent, from the research): this daemon
is a user-space scanner. It can scan on request and notify on
watch events. It can NEVER block a file open or execution; that
requires a Windows minifilter, Linux fanotify with permissions,
or Apple's Endpoint Security entitlement, none of which a public
stdlib project ships. Anyone describing it as on-access
protection is wrong.

API (loopback only, optional shared token via X-Aegis-Token):
  GET  /ping            -> {"status": "ok", "pack": "name@version"}
  POST /scan {"path"}   -> verdict JSON for a file on disk
  POST /scan_name {"name", "data_b64"} -> verdict for submitted bytes
Rules and automaton stay resident in memory, which is where the
throughput win over process-per-scan CLI scanning comes from.
"""
from __future__ import annotations

import base64
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import Engine

MAX_BODY_BYTES = 16 * 1024 * 1024


def handle_request(engine: Engine, method: str, route: str,
                   body: bytes = b"", token: str = "",
                   auth_header: str = "",
                   audit_path: Path | None = None) -> tuple[int, dict]:
    status, doc = _handle(engine, method, route, body, token,
                          auth_header)
    if audit_path is not None:
        entry = {"ts": time.time(), "method": method, "route": route,
                 "status": status,
                 "body_bytes": len(body)}
        with Path(audit_path).open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    return status, doc


def _handle(engine: Engine, method: str, route: str,
            body: bytes = b"", token: str = "",
            auth_header: str = "") -> tuple[int, dict]:
    if token and not hmac.compare_digest(auth_header, token):
        return 401, {"error": "unauthorised"}
    if len(body) > MAX_BODY_BYTES:
        return 413, {"error": "body too large",
                     "limit_bytes": MAX_BODY_BYTES}
    if method == "GET" and route == "/ping":
        return 200, {"status": "ok",
                     "pack": f"{engine.pack.name}@{engine.pack.version}"}
    if method == "POST" and route == "/scan":
        try:
            path = Path(json.loads(body)["path"])
        except Exception:
            return 400, {"error": "body must be JSON with a path field"}
        if not path.is_file():
            return 404, {"error": "no such file"}
        return 200, engine.scan_file(path)
    if method == "POST" and route == "/scan_name":
        try:
            doc = json.loads(body)
            data = base64.b64decode(doc["data_b64"])
            name = str(doc["name"])
        except Exception:
            return 400, {"error": "body must have name and data_b64"}
        return 200, engine.scan_bytes(data, name)
    return 404, {"error": "unknown route"}


def serve(engine: Engine, port: int = 8765, token: str = "",
          audit_path: Path | None = None) -> None:
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(length, MAX_BODY_BYTES + 1)) \
                if length else b""
            status, doc = handle_request(
                engine, method, self.path, body, token,
                self.headers.get("X-Aegis-Token", ""), audit_path)
            payload = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 - stdlib API name
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def log_message(self, *args) -> None:
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
