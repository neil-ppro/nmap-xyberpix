#!/usr/bin/env python3
"""
Zenmap ↔ Nmap CLI parity checks (no GTK import).

1. nmap-xyberpix SIEM / scan-policy long options appear in NmapOptions.LONG_OPTIONS,
   OptionBuilder.py (SIEM tab widgets), and profile_editor.xml (labels/tooltips).
2. Every long option name in maint/data/nmap-long-options-baseline.txt appears in
   Zenmap LONG_OPTIONS except names listed in maint/data/zenmap-nmap-longopt-exceptions.txt
   (update that file when nmap.cc gains new flags you do not expose in Zenmap).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_MAINT = Path(__file__).resolve().parent

XYBERPIX_LONG_NAMES = frozenset(
    {
        "adaptive-rate",
        "auto-hostgroup",
        "decoy-stagger",
        "decoy-stagger-random",
        "ipv6-robust",
        "safe-profile",
        "siem-log",
        "siem-syslog",
        "siem-tag",
    }
)

BASELINE = _MAINT / "data" / "nmap-long-options-baseline.txt"
EXCEPTIONS = _MAINT / "data" / "zenmap-nmap-longopt-exceptions.txt"


def _parse_baseline_names() -> set[str]:
    if not BASELINE.is_file():
        raise FileNotFoundError(BASELINE)
    out: set[str] = set()
    for ln in BASELINE.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.add(ln)
    return out


def _parse_exception_names() -> set[str]:
    if not EXCEPTIONS.is_file():
        return set()
    out: set[str] = set()
    for ln in EXCEPTIONS.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        name = ln.split("#", 1)[0].strip()
        if name:
            out.add(name)
    return out


def _parse_zenmap_long_options(nmap_options_py: str) -> set[str]:
    return set(
        re.findall(r'^\s+\("([^"]+)",\s*option\.', nmap_options_py, re.MULTILINE)
    )


def _check_xyberpix_subset(ntext: str, otext: str, xml_text: str) -> list[str]:
    errors: list[str] = []
    for name in sorted(XYBERPIX_LONG_NAMES):
        needle = f'("{name}", option.'
        if needle not in ntext:
            errors.append(
                f'nmap-xyberpix: missing NmapOptions LONG_OPTIONS entry for "{name}"'
            )
        flag = f"--{name}"
        if flag not in otext:
            errors.append(
                f"nmap-xyberpix: missing OptionBuilder reference for {flag}"
            )
        if f'option="{flag}"' not in xml_text:
            errors.append(
                f"nmap-xyberpix: missing profile_editor.xml option_check for {flag}"
            )
    return errors


def _check_nmap_zenmap_parity(ntext: str) -> list[str]:
    nmap_names = _parse_baseline_names()
    exc = _parse_exception_names()
    zen = _parse_zenmap_long_options(ntext)
    unknown_exc = sorted(exc - nmap_names)
    if unknown_exc:
        return [
            "zenmap-nmap-longopt-exceptions.txt lists unknown names (not in baseline): "
            + ", ".join(unknown_exc)
        ]
    required = nmap_names - exc
    missing = sorted(required - zen)
    if missing:
        return [
            "nmap.cc long options missing from Zenmap NmapOptions.LONG_OPTIONS (or add to "
            "maint/data/zenmap-nmap-longopt-exceptions.txt): "
            + ", ".join(missing)
        ]
    return []


def main() -> int:
    nopt = REPO / "zenmap" / "zenmapCore" / "NmapOptions.py"
    ob = REPO / "zenmap" / "zenmapGUI" / "OptionBuilder.py"
    xml = REPO / "zenmap" / "zenmapCore" / "data" / "misc" / "profile_editor.xml"
    if not nopt.is_file() or not ob.is_file() or not xml.is_file():
        print("Zenmap sources not found; skip or fix paths.", file=sys.stderr)
        return 1

    ntext = nopt.read_text(encoding="utf-8", errors="replace")
    otext = ob.read_text(encoding="utf-8", errors="replace")
    xml_text = xml.read_text(encoding="utf-8", errors="replace")

    errors: list[str] = []
    errors.extend(_check_xyberpix_subset(ntext, otext, xml_text))
    try:
        errors.extend(_check_nmap_zenmap_parity(ntext))
    except FileNotFoundError as e:
        errors.append(str(e))

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    nmap_n = len(_parse_baseline_names())
    zen_n = len(_parse_zenmap_long_options(ntext))
    exc_n = len(_parse_exception_names())
    print(
        "zenmap_parity_ok",
        f"nmap-xyberpix={len(XYBERPIX_LONG_NAMES)}",
        f"nmap_longopts={nmap_n}",
        f"zenmap_longopts={zen_n}",
        f"exceptions={exc_n}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
