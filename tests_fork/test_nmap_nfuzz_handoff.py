"""nmap ↔ nfuzz handoff parsing."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_GUI = _ROOT / "xyberpix-gui"
sys.path.insert(0, str(_GUI))

from xyberpix_gui.nmap_nfuzz_handoff import (  # noqa: E402
    parse_grepable_nmap,
    parse_normal_nmap_output,
    suggest_nfuzz_argv_fragment,
)


def test_grepable_open_ports() -> None:
    text = """
# Nmap 7.98 scan initiated ...
Host: 192.0.2.10 ()     Status: Up
Host: 192.0.2.10 ()     Ports: 22/open/tcp//ssh///,80/open/tcp//http///,443/filtered/tcp/////
"""
    rows = parse_grepable_nmap(text)
    assert len(rows) == 2
    assert rows[0].port == 22 and rows[0].proto == "tcp"
    frag = suggest_nfuzz_argv_fragment(rows[1])
    assert "--proto tcp" in frag
    assert "--dport 80" in frag


def test_normal_table() -> None:
    text = """
PORT     STATE SERVICE
22/tcp   open  ssh
53/udp   open  domain
"""
    rows = parse_normal_nmap_output(text, "10.0.0.5")
    assert len(rows) == 2
    assert rows[1].proto == "udp"
    assert "udp" in suggest_nfuzz_argv_fragment(rows[1])
