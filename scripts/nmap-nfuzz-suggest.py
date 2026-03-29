#!/usr/bin/env python3
"""Suggest nfuzz command lines from Nmap grepable (-oG) or XML (-oX) output (authorized use only)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Repo root: scripts/ -> parent
_ROOT = Path(__file__).resolve().parents[1]
_GUI = _ROOT / "xyberpix-gui"
if _GUI.is_dir():
    sys.path.insert(0, str(_GUI))

from xyberpix_gui.nmap_nfuzz_handoff import (  # noqa: E402
    format_suggestion_lines,
    load_ports_from_file,
)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", help="Path to Nmap -oG or -oX file")
    p.add_argument(
        "--format",
        choices=("grepable", "xml"),
        required=True,
        help="Whether INPUT is grepable (-oG) or XML (-oX)",
    )
    p.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Print count only",
    )
    args = p.parse_args()
    try:
        rows = load_ports_from_file(args.input, args.format)
    except (OSError, ValueError) as e:
        print(f"nmap-nfuzz-suggest: {e}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(len(rows))
        return 0
    sys.stdout.write(format_suggestion_lines(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
