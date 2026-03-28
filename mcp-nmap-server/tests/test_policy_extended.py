"""Extra policy tests: blocklist coverage, fuzz stability, optional nmap SIEM integration."""

from __future__ import annotations

import json
import os
import random
import shutil
import string
import subprocess
from typing import Any

import pytest

from mcp_nmap.server import (
    _SAFE_MODE_LONG_BASE_BLOCKLIST,
    _SAFE_MODE_LONG_PREFIX_BLOCKLIST,
    _scan_options_policy_error,
    _validate_scan_options,
    nmap_dry_run,
)


def _nmap_exe() -> str | None:
    return os.environ.get("NMAP_MCP_BINARY", "").strip() or shutil.which("nmap")


def _nmap_help_mentions_siem() -> bool:
    exe = _nmap_exe()
    if not exe:
        return False
    try:
        p = subprocess.run(
            [exe, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except OSError:
        return False
    blob = (p.stdout or "") + (p.stderr or "")
    return "siem-log" in blob


@pytest.mark.parametrize(
    "scan_options",
    [
        ["--resume", "scan.xml"],
        ["--iR=10"],
        ["--proxies", "http://127.0.0.1:9"],
        ["--proxy", "http://127.0.0.1:9"],
        ["--ssh-bounce", "user@jump.example"],
        ["--ssh-bounce-port", "2222"],
        ["--sI", "zombie:port"],
        ["--datadir=/tmp"],
        ["--datadir", "/tmp"],
        ["--servicedb=/x"],
        ["--versiondb=/x"],
        ["--stylesheet=/x"],
        ["--excludefile=/x"],
        ["--append-output"],
        ["--siem-log", "/var/tmp/should-not-be-used.ndjson"],
        ["--siem-log=/etc/passwd"],
    ],
)
def test_safe_mode_blocks_tabled_long_flags(scan_options: list[str]) -> None:
    r = nmap_dry_run(["-sn", *scan_options], ["127.0.0.1"])
    assert r["ok"] is False


def test_blocklist_constants_cover_prefix_entries() -> None:
    for bl in _SAFE_MODE_LONG_PREFIX_BLOCKLIST:
        assert bl.startswith("--"), bl


def test_blocklist_constants_cover_base_entries() -> None:
    for b in _SAFE_MODE_LONG_BASE_BLOCKLIST:
        assert b.startswith("--"), b


def test_policy_fuzz_random_tokens_no_crash() -> None:
    """Random argv fragments must not crash the policy checker."""
    rng = random.Random(0)
    alphabet = string.ascii_letters + string.digits + "_-./:=,@+"
    for _ in range(400):
        ntok = rng.randint(0, 10)
        toks = [
            "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
            for _ in range(ntok)
        ]
        try:
            _validate_scan_options(toks)
        except ValueError:
            continue
        err = _scan_options_policy_error(toks)
        assert err is None or isinstance(err, str)


@pytest.mark.skipif(
    os.environ.get("NMAP_MCP_TEST_LIVE_SIEM", "").strip() != "1",
    reason="Set NMAP_MCP_TEST_LIVE_SIEM=1 for live nmap --siem-log schema check",
)
@pytest.mark.skipif(
    not _nmap_help_mentions_siem(),
    reason="No nmap with --siem-log in PATH (set NMAP_MCP_BINARY or install nmap-ppro build)",
)
def test_siem_ndjson_schema_on_stdout() -> None:
    exe = _nmap_exe()
    assert exe
    env = os.environ.copy()
    env.pop("NMAP_MCP_ALLOW_UNSAFE_CLI", None)
    r = subprocess.run(
        [exe, "-sn", "127.0.0.1", "--siem-log", "-"],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    combined = (r.stdout or "") + "\n" + (r.stderr or "")
    events: list[dict[str, Any]] = []
    for line in combined.splitlines():
        t = line.strip()
        if len(t) < 2 or not t.startswith("{") or not t.endswith("}"):
            continue
        try:
            obj = json.loads(t)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "event" in obj:
            events.append(obj)
    assert events, "expected SIEM NDJSON lines with event field"
    for ev in events:
        assert ev.get("schema_version") == 1
        ts = ev.get("ts")
        assert isinstance(ts, str) and ts.endswith("Z")
        assert isinstance(ev.get("event"), str)
