"""Policy file + audit helpers for nmap-mcp-server."""

from __future__ import annotations

import json

import pytest

from mcp_nmap.audit_log import audit_append
from mcp_nmap.policy_file import (
    load_mcp_policy,
    policy_cap_timeout,
    policy_check_max_targets,
    policy_scan_options_error,
    policy_targets_error,
)


def test_policy_scan_option_prefix(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_text(
        json.dumps({"disallowed_scan_option_prefixes": ["--script", "--script="]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    pol = load_mcp_policy()
    assert policy_scan_options_error(["-sn", "--script", "foo"], pol) is not None
    assert policy_scan_options_error(["-sn"], pol) is None


def test_policy_max_targets(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_text(json.dumps({"max_targets": 2}), encoding="utf-8")
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    pol = load_mcp_policy()
    assert policy_check_max_targets(["a", "b", "c"], pol) is not None
    assert policy_check_max_targets(["a", "b"], pol) is None


def test_policy_hostnames_only(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_text(
        json.dumps({"allowed_hostnames": ["lab.local", "scanme.nmap.org"]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    pol = load_mcp_policy()
    assert policy_targets_error(["lab.local"], pol) is None
    assert policy_targets_error(["LAB.LOCAL."], pol) is None
    assert policy_targets_error(["evil.example"], pol) is not None


def test_policy_file_size_cap(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_bytes(b"x" * (300 * 1024))
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    with pytest.raises(RuntimeError, match="exceeds"):
        load_mcp_policy()


def test_policy_cidr_allow(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_text(
        json.dumps({"allowed_target_cidrs": ["127.0.0.0/8"]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    pol = load_mcp_policy()
    assert policy_targets_error(["127.0.0.1"], pol) is None
    assert policy_targets_error(["10.0.0.1"], pol) is not None


def test_policy_cap_timeout(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    polf = tmp_path / "p.json"
    polf.write_text(json.dumps({"max_timeout_seconds": 30}), encoding="utf-8")
    monkeypatch.setenv("NMAP_MCP_POLICY_FILE", str(polf))
    pol = load_mcp_policy()
    assert policy_cap_timeout(120, pol) == 30


def test_audit_append_writes_line(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    logf = tmp_path / "audit.ndjson"
    monkeypatch.setenv("NMAP_MCP_AUDIT_LOG", str(logf))
    audit_append("test_event", ok=True, x=1)
    data = logf.read_text(encoding="utf-8").strip()
    row = json.loads(data)
    assert row["event"] == "test_event"
    assert row["ok"] is True


def test_audit_truncates_long_strings(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    logf = tmp_path / "audit.ndjson"
    monkeypatch.setenv("NMAP_MCP_AUDIT_LOG", str(logf))
    huge = "E" * 50_000
    audit_append("big", msg=huge)
    row = json.loads(logf.read_text(encoding="utf-8").strip())
    assert row["event"] == "big"
    assert len(row["msg"]) < len(huge)
    assert row["msg"].endswith("[...]")
