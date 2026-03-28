#!/usr/bin/env python3
"""
Local maint harness: HTTP fixture + Nmap against 127.0.0.1 for nmap-xyberpix offsec NSE.

Requires a working `nmap` (PATH or NMAP_SELFTEST_BINARY). Passes --datadir to
this repository root so fork scripts and nselib load.

Usage:
  python3 maint/nse_offsec_selftest.py
"""

from __future__ import annotations

import http.server
import os
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Ports where shortport.http matches (see nselib/shortport.lua LIKELY_HTTP_PORTS).
_CANDIDATE_HTTP_PORTS = (
    8080,
    8000,
    8180,
    8088,
    8443,
    7080,
    5800,
    3872,
    631,
    80,
    443,
)


def _pick_http_like_port() -> int:
    for p in _CANDIDATE_HTTP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            s.close()
            continue
        s.close()
        return int(p)
    raise RuntimeError(
        "Could not bind 127.0.0.1 on any candidate HTTP-like port; "
        "free one of: " + ",".join(str(x) for x in _CANDIDATE_HTTP_PORTS)
    )


class _QuietHTTPServer(http.server.HTTPServer):
    def handle_error(self, _request: object, _client_address: object) -> None:
        # Nmap may reset connections during service probes; avoid traceback noise.
        return


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path.startswith("/openapi.json"):
            body = b'{"openapi":"3.0.0","paths":{"/v1/debug":{}}}'
        elif path.startswith("/version"):
            body = b'{"major":"1","minor":"24","gitVersion":"v1.24.0"}'
        elif path.startswith("/api/v1/namespaces"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="kubernetes"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif path == "/api" or path.startswith("/api/"):
            body = (
                b'{"kind":"APIVersions","versions":["v1"],'
                b'"serverAddressByClientCIDRs":[]}'
            )
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _run_nmap(
    port: int, extra: list[str], *, debug: bool = False
) -> subprocess.CompletedProcess[str]:
    binary = os.environ.get("NMAP_SELFTEST_BINARY", "nmap").strip() or "nmap"
    if not shutil.which(binary) and not Path(binary).is_file():
        raise FileNotFoundError(f"nmap not found ({binary!r}); set NMAP_SELFTEST_BINARY")

    cmd = [binary]
    if debug:
        # stdnse.format_output(false, ...) omits text unless debugging >= 1
        cmd.append("-d")
    cmd.extend(
        [
            "--datadir",
            str(REPO_ROOT),
            "-p",
            str(port),
            "-Pn",
            "-oX",
            "-",
        ]
    )
    cmd.extend(extra)
    cmd.append("127.0.0.1")
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def main() -> int:
    port = _pick_http_like_port()
    server = _QuietHTTPServer(("127.0.0.1", port), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    failures: list[str] = []
    try:
        try:
            r = _run_nmap(port, ["--script", "http-openapi-map"])
        except FileNotFoundError as e:
            print(f"SKIP: {e}", file=sys.stderr)
            return 0

        if r.returncode != 0:
            failures.append(f"http-openapi-map rc={r.returncode} stderr={r.stderr!r}")
        elif "openapi" not in r.stdout.lower() and "debug" not in r.stdout.lower():
            failures.append("http-openapi-map: expected openapi/debug in -oX output")

        r2 = _run_nmap(port, ["--script", "http-ssrf-canary"], debug=True)
        if "intrusive" not in (r2.stdout + r2.stderr).lower():
            failures.append("http-ssrf-canary: expected intrusive gate message")

        r3 = _run_nmap(port, ["--script", "k8s-api-anon-audit"])
        if r3.returncode != 0:
            failures.append(f"k8s-api-anon-audit rc={r3.returncode} stderr={r3.stderr!r}")
        else:
            comb = (r3.stdout + r3.stderr).lower()
            if "anonymous_json" not in comb and "auth_required" not in comb:
                failures.append(
                    "k8s-api-anon-audit: expected anonymous_json or auth_required in output"
                )
    finally:
        server.shutdown()
        server.server_close()

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("nse_offsec_selftest: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
