#!/usr/bin/env python3
"""
Demonstrates MCP safe-mode rejection of scan_options that used to bypass policy:

  * Long --oN /path (file write) — now blocked like short -oN.
  * Long --iL path (file read) — now blocked like short -iL.
  * -iR / --iR (random targets) — blocked.
  * --resume, --proxies — blocked.

Install deps from mcp-nmap-server (see MCP-TARGET PoC), then:

  cd mcp-nmap-server && .venv/bin/python \\
    ../docs/security/poc_mcp_scan_options_policy_bypass_demonstration.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_MCP = _ROOT / "mcp-nmap-server"
if _MCP.is_dir():
    sys.path.insert(0, str(_MCP))

try:
    from mcp_nmap.server import nmap_dry_run
except ModuleNotFoundError as e:
    print("Install mcp-nmap-server deps:", e, file=sys.stderr)
    sys.exit(2)

_CASES: list[tuple[str, list[str]]] = [
    ("long --oN file write", ["--oN", "/tmp/mcp-policy-poc.xml", "-sn"]),
    ("long --iL file read", ["--iL", "/etc/passwd", "-sn"]),
    ("-iR random targets", ["-iR", "5", "-sn"]),
    ("--resume", ["--resume", "/nonexistent/nmap-resume.xml"]),
    ("--proxies", ["--proxies", "http://127.0.0.1:9", "-sn"]),
]


def main() -> int:
    tgt = ["127.0.0.1"]
    failed = False
    for name, opts in _CASES:
        r = nmap_dry_run(opts, tgt)
        if r.get("ok") is True:
            print(f"FAIL: {name} was accepted; argv={r.get('argv')!r}")
            failed = True
        else:
            print(f"OK: {name} -> {r.get('error')}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
