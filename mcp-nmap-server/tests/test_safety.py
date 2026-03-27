"""Unit tests for MCP Nmap server validation helpers."""

import os

import pytest

from mcp_nmap.server import (
    _is_loopback_target,
    _targets_allowed_for_scope,
    _validate_scan_options,
    _validate_targets,
    nmap_dry_run,
)


def test_validate_rejects_shellish_chars() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        _validate_scan_options(["-p", "80;rm -rf /"])


def test_validate_targets_nonempty() -> None:
    with pytest.raises(ValueError, match="At least one target"):
        _validate_targets([])


def test_loopback_targets() -> None:
    assert _is_loopback_target("127.0.0.1")
    assert _is_loopback_target("::1")
    assert _is_loopback_target("localhost")
    assert _is_loopback_target("127.0.0.0/8")
    assert not _is_loopback_target("scanme.nmap.org")
    assert not _is_loopback_target("192.168.1.1")


def test_scope_any_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NMAP_MCP_ALLOW_ANY_TARGET", raising=False)
    ok, err = _targets_allowed_for_scope(["192.168.1.1"], "any")
    assert ok is False
    assert "NMAP_MCP_ALLOW_ANY_TARGET" in err


def test_dry_run_loopback_ok() -> None:
    r = nmap_dry_run(["-sn"], ["127.0.0.1"])
    assert r["ok"] is True
    assert "nmap" in r["argv"][0].lower() or os.path.basename(r["argv"][0]) == "nmap"


def test_dry_run_rejects_non_loopback_default_scope() -> None:
    r = nmap_dry_run(["-sn"], ["192.168.1.1"])
    assert r["ok"] is False
    assert "loopback" in r["error"].lower()
