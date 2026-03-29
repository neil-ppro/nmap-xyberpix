"""Deeper ngit tests: scanning, parse_extra_regex, CLI branches."""

from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_line_matches_keywords(ngit_mod) -> None:
    assert ngit_mod.line_matches_keywords("hello", []) is True
    assert ngit_mod.line_matches_keywords("Hello world", ["ell"]) is True
    assert ngit_mod.line_matches_keywords("nope", ["x", "yz"]) is False


def test_scan_line_findings_match_cap(ngit_mod) -> None:
    cap = ngit_mod.NGIT_MAX_REGEX_MATCHES_PER_LINE
    line = "x" * (cap * 4)
    rules = [("dot", re.compile(r"."))]
    out = ngit_mod.scan_line_findings([line], rules, [])
    assert len(out) == cap


def test_scan_pem_match_cap(ngit_mod) -> None:
    cap = ngit_mod.NGIT_MAX_PEM_MATCHES_PER_FILE
    mid = "A" * 80
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + mid
        + "\n-----END RSA PRIVATE KEY-----\n"
    )
    text = block * (cap + 5)
    out = ngit_mod.scan_pem_findings(text, include_certificates=False)
    assert len(out) == cap


def test_parse_extra_regex_ok(ngit_mod) -> None:
    got = ngit_mod.parse_extra_regex_args(["demo_pat=[a]{2}"])
    assert len(got) == 1
    assert got[0][0] == "demo_pat"


def test_parse_extra_regex_bad_label_exits(monkeypatch, ngit_mod) -> None:
    monkeypatch.setattr(ngit_mod.sys, "exit", lambda c: (_ for _ in ()).throw(SystemExit(c)))
    with pytest.raises(SystemExit):
        ngit_mod.parse_extra_regex_args(["9bad=[a]"])


def test_parse_extra_regex_missing_equals_exits(monkeypatch, ngit_mod) -> None:
    monkeypatch.setattr(ngit_mod.sys, "exit", lambda c: (_ for _ in ()).throw(SystemExit(c)))
    with pytest.raises(SystemExit):
        ngit_mod.parse_extra_regex_args(["nope"])


def test_scan_single_file_skips_symlink(ngit_mod, tmp_path: Path) -> None:
    real = tmp_path / "real.txt"
    real.write_text('password="not_a_real_secret_value"\n', encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("cannot create symlink")
    pwd_rules = [r for r in ngit_mod.RULES if r[0] == "password_assignment"]
    assert pwd_rules
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        n_link = ngit_mod.scan_single_file(
            str(link),
            "link.txt",
            "o/r",
            pwd_rules,
            True,
            False,
            [],
            [],
            [],
            False,
        )
        n_real = ngit_mod.scan_single_file(
            str(real),
            "real.txt",
            "o/r",
            pwd_rules,
            True,
            False,
            [],
            [],
            [],
            False,
        )
    assert n_link == 0
    assert n_real >= 1


def test_main_keyword_scan_requires_keyword(ngit_path) -> None:
    r = subprocess.run(
        [
            sys.executable,
            str(ngit_path),
            "--authorized",
            "--repo",
            "nmap/nmap",
            "--keyword-scan",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 2
    assert "keyword" in (r.stderr + r.stdout).lower()
