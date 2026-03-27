"""Tests for nmap_parse_xml_summary (defusedxml-based)."""

from __future__ import annotations

import pytest

from mcp_nmap.server import _parse_nmap_xml_summary, _truncate_utf8_text, nmap_parse_xml_summary

_MINIMAL_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished timestr="Mon Jan 1 00:00:00 2026"/>
    <hosts up="1" down="0"/>
  </runstats>
</nmaprun>
"""


def test_parse_minimal_xml() -> None:
    r = _parse_nmap_xml_summary(_MINIMAL_NMAP_XML)
    assert r["ok"] is True
    assert len(r["hosts"]) == 1
    h = r["hosts"][0]
    assert h["up"] is True
    assert h["addresses"][0]["addr"] == "127.0.0.1"
    assert h["hostnames"] == ["localhost"]
    assert h["ports"][0]["port"] == "22"
    assert h["ports"][0]["state"] == "open"
    assert h["ports"][0]["service"] == "ssh"
    assert r["runstats"].get("hosts_up") == 1
    assert r["runstats"].get("finished_timestr")


def test_parse_invalid_xml() -> None:
    r = _parse_nmap_xml_summary("<not>xml")
    assert r["ok"] is False
    assert "invalid XML" in (r.get("error") or "")


def test_parse_rejects_huge_input(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_nmap.server as srv

    monkeypatch.setattr(srv, "_MAX_XML_TEXT_BYTES", 500)
    r = srv._parse_nmap_xml_summary("x" * 501)
    assert r["ok"] is False
    assert "too large" in (r.get("error") or "").lower()


def test_tool_wrapper_matches() -> None:
    assert nmap_parse_xml_summary(_MINIMAL_NMAP_XML)["ok"] is True


def test_truncate_utf8_text() -> None:
    s = "a" * 100
    out, tr = _truncate_utf8_text(s, 2000)
    assert tr is False and out == s
    out2, tr2 = _truncate_utf8_text("é" * 100, 3)
    assert tr2 is True
    assert "truncated" in out2.lower()
