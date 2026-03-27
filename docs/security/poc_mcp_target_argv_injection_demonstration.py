#!/usr/bin/env python3
"""
Demonstration: before the target argv hardening, Nmap-style option tokens in the
MCP `targets` list could be appended after legitimate targets and still parsed
by Nmap as flags (getopt_long_only), bypassing scan_options-only policy.

Run (after fix): validation rejects these targets — this script asserts that.

Requires the MCP package and its dependencies (FastMCP), e.g.:

  cd mcp-nmap-server && python3 -m venv .venv && .venv/bin/pip install -e .
  .venv/bin/python ../docs/security/poc_mcp_target_argv_injection_demonstration.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Prefer mcp-nmap-server next to this repo layout (docs/security/ -> parents[2] = root)
_ROOT = Path(__file__).resolve().parents[2]
_MCP = _ROOT / "mcp-nmap-server"
if _MCP.is_dir():
    sys.path.insert(0, str(_MCP))

try:
    from mcp_nmap.server import nmap_dry_run
except ModuleNotFoundError as e:
    print(
        "Missing dependency (install from mcp-nmap-server, see docstring):",
        e,
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> int:
    # Malicious pattern: real loopback target then extra argv tokens.
    r = nmap_dry_run(["-sn"], ["127.0.0.1", "-oN", "/tmp/mcp-inject-demo.xml"])
    if r.get("ok") is True:
        print("UNEXPECTED: dry_run accepted injected -oN (fix missing?)")
        print("argv:", r.get("argv"))
        return 1

    err = (r.get("error") or "").lower()
    if "start with" in err or "cli option" in err or "argument injection" in err:
        print("OK: target argv injection blocked:", r.get("error"))
        return 0

    print("Partial: rejected but unexpected message:", r.get("error"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
