#!/usr/bin/env python3
"""
Compare Nmap long option names in nmap.cc against a committed baseline.

When upstream (or this fork) adds a new `{"name", ...}` entry to `long_options[]`,
CI fails until a maintainer runs `maint/update_mcp_longopt_baseline.py` and
reviews `mcp_nmap/server.py` safe-mode policy for bypass risk.
"""
from __future__ import annotations

import sys
from pathlib import Path

_MAINT = Path(__file__).resolve().parent
sys.path.insert(0, str(_MAINT))
from nmap_longopts_from_cc import parse_long_options_from_nmap_cc  # noqa: E402

REPO = _MAINT.parent
NMAP_CC = REPO / "nmap.cc"
BASELINE = REPO / "maint" / "data" / "nmap-long-options-baseline.txt"


def main() -> int:
    if not NMAP_CC.is_file():
        print("nmap.cc not found", file=sys.stderr)
        return 1
    current = parse_long_options_from_nmap_cc(NMAP_CC)
    if not BASELINE.is_file():
        print(
            f"Missing baseline {BASELINE}. Run: python3 maint/update_mcp_longopt_baseline.py",
            file=sys.stderr,
        )
        return 1
    expected = [
        ln.strip()
        for ln in BASELINE.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if current != expected:
        cur_set, exp_set = set(current), set(expected)
        added = sorted(cur_set - exp_set)
        removed = sorted(exp_set - cur_set)
        print("nmap.cc long_options[] differs from baseline.", file=sys.stderr)
        if added:
            print("  Added in nmap.cc (review MCP safe mode):", ", ".join(added), file=sys.stderr)
        if removed:
            print("  Removed from nmap.cc:", ", ".join(removed), file=sys.stderr)
        print("  Fix: python3 maint/update_mcp_longopt_baseline.py", file=sys.stderr)
        print(
            "  Then audit mcp-nmap-server/mcp_nmap/server.py _scan_options_policy_error.",
            file=sys.stderr,
        )
        return 1
    print("mcp_longopt_baseline_ok", len(current), "options")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
