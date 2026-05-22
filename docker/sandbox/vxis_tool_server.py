#!/usr/bin/env python3
"""Minimal VXIS sandbox tool server.

Runs inside the sandbox container and executes shell commands on request.
Only stdlib is used so the server works in the lightweight Debian image.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_CHARS = 200_000


def _json_bytes(payload: dict[str, Any], status: int = 200) -> tuple[int, bytes]:
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    return status, body


class Handler(BaseHTTPRequestHandler):
    server_version = "vxis-tool-server/0.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/health":
            self._send_json({"ok": True, "service": "vxis-tool-server"})
            return
        self._send_json({"ok": False, "error": "not_found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/execute":
            self._send_json({"ok": False, "error": "not_found"}, status=404)
            return
        if not self._authorized():
            self._send_json({"ok": False, "error": "unauthorized"}, status=401)
            return

        try:
            payload = self._read_json()
            command = str(payload.get("command") or "").strip()
            timeout = float(payload.get("timeout") or 120.0)
            cwd = str(payload.get("cwd") or "/workspace")
        except Exception as exc:
            self._send_json({"ok": False, "error": f"bad_request:{exc}"}, status=400)
            return

        if not command:
            self._send_json({"ok": False, "error": "missing_command"}, status=400)
            return
        timeout = max(1.0, min(600.0, timeout))
        if not os.path.isdir(cwd):
            cwd = "/workspace"

        try:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            self._send_json(
                {
                    "ok": completed.returncode == 0,
                    "exit_code": completed.returncode,
                    "stdout": stdout[:MAX_OUTPUT_CHARS],
                    "stderr": stderr[:MAX_OUTPUT_CHARS],
                    "stdout_truncated": len(stdout) > MAX_OUTPUT_CHARS,
                    "stderr_truncated": len(stderr) > MAX_OUTPUT_CHARS,
                    "timeout": False,
                }
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            self._send_json(
                {
                    "ok": False,
                    "exit_code": 124,
                    "stdout": stdout[:MAX_OUTPUT_CHARS],
                    "stderr": stderr[:MAX_OUTPUT_CHARS],
                    "stdout_truncated": len(stdout) > MAX_OUTPUT_CHARS,
                    "stderr_truncated": len(stderr) > MAX_OUTPUT_CHARS,
                    "timeout": True,
                }
            )
        except Exception as exc:
            self._send_json({"ok": False, "error": str(exc), "exit_code": -1}, status=500)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _authorized(self) -> bool:
        token = getattr(self.server, "auth_token", "")
        header = self.headers.get("Authorization", "")
        return bool(token) and header == f"Bearer {token}"

    def _read_json(self) -> dict[str, Any]:
        raw_len = int(self.headers.get("Content-Length") or "0")
        if raw_len <= 0:
            return {}
        if raw_len > MAX_REQUEST_BYTES:
            raise ValueError("request_too_large")
        raw = self.rfile.read(raw_len)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("payload_must_be_object")
        return data

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        status, body = _json_bytes(payload, status=status)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--token", default=os.environ.get("VXIS_TOOL_SERVER_TOKEN", ""))
    args = parser.parse_args()
    if not args.token:
        raise SystemExit("missing --token")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.auth_token = args.token  # type: ignore[attr-defined]
    server.serve_forever()


if __name__ == "__main__":
    main()
