"""Unit and CLI smoke tests for ngit (loaded from ngit/ngit)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_github_full_name_allowed(ngit_mod) -> None:
    assert ngit_mod.github_full_name_allowed("nmap/nmap") is True
    assert ngit_mod.github_full_name_allowed("foo/bar") is True
    assert ngit_mod.github_full_name_allowed(".github/foo") is True
    assert ngit_mod.github_full_name_allowed("evil/name;rm") is False
    assert ngit_mod.github_full_name_allowed("evil/cmd") is True
    assert ngit_mod.github_full_name_allowed("a") is False
    assert ngit_mod.github_full_name_allowed("a/b/c") is False
    assert ngit_mod.github_full_name_allowed(".") is False
    assert ngit_mod.github_full_name_allowed("..") is False
    assert ngit_mod.github_full_name_allowed("../x") is False


def test_should_skip_path_parent(ngit_mod) -> None:
    assert ngit_mod.should_skip_path("src/../etc/passwd") is True
    assert ngit_mod.should_skip_path("ok/file.txt") is False


def test_sanitize_finding_field(ngit_mod) -> None:
    s = ngit_mod.sanitize_finding_field("a\nb\x00c")
    assert "\n" not in s
    assert "\x00" not in s


def test_rule_type_allowed(ngit_mod) -> None:
    assert ngit_mod.rule_type_allowed("aws_x", [], []) is True
    assert ngit_mod.rule_type_allowed("aws_x", ["aws*"], []) is True
    assert ngit_mod.rule_type_allowed("pem_rsa", ["pem_*"], []) is True
    assert ngit_mod.rule_type_allowed("aws_x", ["github*"], []) is False
    assert ngit_mod.rule_type_allowed("aws_x", ["*"], ["aws*"]) is False


def test_validate_token_rejects_control(monkeypatch, ngit_mod) -> None:
    exits: list[int] = []

    def capture_exit(code: int) -> None:
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(ngit_mod.sys, "exit", capture_exit)
    with pytest.raises(SystemExit):
        ngit_mod.validate_github_token_for_transport("ghp_" + "a" * 10 + "\x01")
    assert exits == [2]


def test_validate_token_ok(ngit_mod) -> None:
    assert ngit_mod.validate_github_token_for_transport(None) is None
    assert ngit_mod.validate_github_token_for_transport("  ") is None
    t = ngit_mod.validate_github_token_for_transport("ghp_abcdef01234567890123456789012abcd")
    assert t is not None
    assert t.startswith("ghp_")


def test_main_version(ngit_path) -> None:
    r = subprocess.run(
        [sys.executable, str(ngit_path), "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 0
    assert "ngit" in r.stdout.lower()


def test_main_refuses_unauthorized(ngit_path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "NGIT_AUTHORIZED"}
    r = subprocess.run(
        [sys.executable, str(ngit_path), "--repo", "a/b"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert r.returncode == 2
    assert "authorized" in (r.stderr + r.stdout).lower()


def test_main_invalid_repo_slug(ngit_path) -> None:
    r = subprocess.run(
        [sys.executable, str(ngit_path), "--authorized", "--repo", "evil/name;rm"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 2
