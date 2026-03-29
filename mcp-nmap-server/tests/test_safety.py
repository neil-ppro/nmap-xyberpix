"""Unit tests for MCP Nmap server validation helpers."""

import os
from pathlib import Path

import pytest

from mcp_nmap.server import (
    _is_loopback_target,
    _nmap_binary,
    _targets_allowed_for_scope,
    _validate_scan_options,
    _validate_targets,
    nmap_dry_run,
    nmap_offsec_dry_run,
    nmap_offsec_list_presets,
)


def test_validate_rejects_shellish_chars() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        _validate_scan_options(["-p", "80;rm -rf /"])


def test_nmap_binary_env_rejects_shell_metacharacters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NMAP_MCP_BINARY", "/usr/bin/nmap;evil")
    with pytest.raises(ValueError, match="forbidden"):
        _nmap_binary()


def test_nmap_binary_env_requires_regular_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "not-there-nmap"
    monkeypatch.setenv("NMAP_MCP_BINARY", str(missing))
    with pytest.raises(RuntimeError, match="regular file"):
        _nmap_binary()


def test_nmap_binary_env_accepts_executable_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "fake-nmap"
    p.write_text("#!/bin/sh\necho nmap\n", encoding="utf-8")
    p.chmod(0o755)
    monkeypatch.setenv("NMAP_MCP_BINARY", str(p))
    assert _nmap_binary() == str(p.resolve())


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


def test_policy_blocks_script() -> None:
    r = nmap_dry_run(["--script=default", "-sn"], ["127.0.0.1"])
    assert r["ok"] is False
    assert "script" in r["error"].lower()


def test_policy_blocks_A_and_iL() -> None:
    assert nmap_dry_run(["-A"], ["127.0.0.1"])["ok"] is False
    assert nmap_dry_run(["-iL", "hosts.txt"], ["127.0.0.1"])["ok"] is False


def test_policy_blocks_long_form_iL() -> None:
    r = nmap_dry_run(["--iL", "/etc/passwd", "-sn"], ["127.0.0.1"])
    assert r["ok"] is False
    assert "iL" in (r.get("error") or "")


def test_policy_blocks_long_form_oN_file() -> None:
    r = nmap_dry_run(["--oN", "/tmp/out.xml", "-sn"], ["127.0.0.1"])
    assert r["ok"] is False
    assert "stdout" in (r.get("error") or "").lower() or "safe mode" in (
        r.get("error") or ""
    ).lower()
    r2 = nmap_dry_run(["--oN=/tmp/out.xml", "-sn"], ["127.0.0.1"])
    assert r2["ok"] is False


def test_policy_allows_long_form_oX_stdout() -> None:
    r = nmap_dry_run(["--oX", "-", "-sn"], ["127.0.0.1"])
    assert r["ok"] is True


def test_policy_blocks_iR_random_targets() -> None:
    r = nmap_dry_run(["-iR", "10", "-sn"], ["127.0.0.1"])
    assert r["ok"] is False


def test_policy_blocks_resume_and_proxies() -> None:
    assert nmap_dry_run(["--resume", "scan.xml"], ["127.0.0.1"])["ok"] is False
    assert nmap_dry_run(["--proxies", "http://127.0.0.1:9"], ["127.0.0.1"])[
        "ok"
    ] is False
    assert nmap_dry_run(["--ssh-bounce", "u@h"], ["127.0.0.1"])["ok"] is False
    assert nmap_dry_run(["--ssh-bounce-port", "2222"], ["127.0.0.1"])["ok"] is False


def test_policy_blocks_double_dash() -> None:
    r = nmap_dry_run(["-sn", "--", "evil.example"], ["127.0.0.1"])
    assert r["ok"] is False
    assert "targets" in r["error"].lower()


def test_policy_allows_stdout_oX() -> None:
    r = nmap_dry_run(["-sn", "-oX", "-"], ["127.0.0.1"])
    assert r["ok"] is True


def test_unsafe_cli_env_allows_script(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NMAP_MCP_ALLOW_UNSAFE_CLI", "1")
    r = nmap_dry_run(["--script=default", "-sn"], ["127.0.0.1"])
    assert r["ok"] is True


def test_offsec_list_presets() -> None:
    r = nmap_offsec_list_presets()
    assert r["ok"] is True
    ids = {p["id"] for p in r["presets"]}
    assert "http_discovery" in ids
    assert "intrusive_canaries" in ids


def test_offsec_dry_run_loopback_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NMAP_MCP_DATADIR", raising=False)
    r = nmap_offsec_dry_run("http_discovery", ["127.0.0.1"])
    assert r["ok"] is True
    assert "--script" in r["argv"]


def test_offsec_dry_run_intrusive_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NMAP_MCP_OFFSEC_INTRUSIVE", raising=False)
    r = nmap_offsec_dry_run(
        "intrusive_canaries",
        ["127.0.0.1"],
        allow_intrusive_offsec=False,
    )
    assert r["ok"] is False


def test_offsec_dry_run_intrusive_ok_with_env_and_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NMAP_MCP_OFFSEC_INTRUSIVE", "1")
    r = nmap_offsec_dry_run(
        "intrusive_canaries",
        ["127.0.0.1"],
        allow_intrusive_offsec=True,
    )
    assert r["ok"] is True
    assert "http-ssrf-canary" in " ".join(r["argv"])


def test_offsec_rejects_bad_extra() -> None:
    r = nmap_offsec_dry_run(
        "http_discovery",
        ["127.0.0.1"],
        extra_scan_options=["--script=default"],
    )
    assert r["ok"] is False


def test_targets_reject_nmap_option_injection() -> None:
    r = nmap_dry_run(["-sn"], ["127.0.0.1", "-oN", "/tmp/x"])
    assert r["ok"] is False
    assert "cli option" in (r.get("error") or "").lower()


def test_targets_reject_double_dash() -> None:
    r = nmap_dry_run(["-sn"], ["--"])
    assert r["ok"] is False


def test_targets_allow_ipv6_loopback() -> None:
    r = nmap_dry_run(["-sn"], ["::1"])
    assert r["ok"] is True


def test_argv_rejects_nul_byte() -> None:
    r = nmap_dry_run(["-sn"], ["127.0.0.1\0evil"])
    assert r["ok"] is False


def test_offsec_preset_id_too_long() -> None:
    r = nmap_offsec_dry_run("x" * 200, ["127.0.0.1"])
    assert r["ok"] is False
