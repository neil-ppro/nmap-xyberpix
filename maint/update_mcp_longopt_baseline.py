#!/usr/bin/env python3
"""Regenerate maint/data/nmap-long-options-baseline.txt from nmap.cc."""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "maint"))
from nmap_longopts_from_cc import parse_long_options_from_nmap_cc  # noqa: E402

OUT = REPO / "maint" / "data" / "nmap-long-options-baseline.txt"


def main() -> int:
    names = parse_long_options_from_nmap_cc(REPO / "nmap.cc")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Generated from nmap.cc long_options[]; do not edit by hand.\n"
        "# Regenerate: python3 maint/update_mcp_longopt_baseline.py\n"
    )
    OUT.write_text(header + "\n".join(names) + "\n", encoding="utf-8")
    print("wrote", OUT, len(names), "names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
