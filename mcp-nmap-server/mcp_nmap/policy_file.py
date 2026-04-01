"""Optional JSON policy file (NMAP_MCP_POLICY_FILE) for MCP scan constraints."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
from typing import Any

_ENV_POLICY = "NMAP_MCP_POLICY_FILE"
# Cap file size to limit memory/CPU (json.load on multi-megabyte policy).
_MAX_POLICY_FILE_BYTES = 256 * 1024

_policy_lock = threading.Lock()
# (path, mtime_ns, parsed_dict) — invalidated on path change or mtime change.
_policy_cache: tuple[str, int, dict[str, Any]] | None = None


def _policy_mtime_ns(path: str) -> int:
    st = os.stat(path)
    ns = getattr(st, "st_mtime_ns", None)
    if ns is not None:
        return int(ns)
    return int(st.st_mtime * 1_000_000_000)


def _read_policy_file_limited(path: str) -> bytes:
    with open(path, "rb") as f:
        raw = f.read(_MAX_POLICY_FILE_BYTES + 1)
    if len(raw) > _MAX_POLICY_FILE_BYTES:
        raise RuntimeError(
            f"{_ENV_POLICY}: file exceeds {_MAX_POLICY_FILE_BYTES} bytes ({path!r})."
        )
    return raw


def load_mcp_policy() -> dict[str, Any]:
    global _policy_cache
    path = os.environ.get(_ENV_POLICY, "").strip()
    if not path or "\x00" in path or len(path) > 4096:
        with _policy_lock:
            _policy_cache = None
        return {}
    with _policy_lock:
        try:
            mtime_ns = _policy_mtime_ns(path)
        except OSError as e:
            raise RuntimeError(f"{_ENV_POLICY}: cannot stat: {e}") from e
        if _policy_cache is not None:
            cpath, cms, cdata = _policy_cache
            if cpath == path and cms == mtime_ns:
                return dict(cdata)
        try:
            raw = _read_policy_file_limited(path)
            data = json.loads(raw.decode("utf-8"))
        except OSError as e:
            raise RuntimeError(f"{_ENV_POLICY}: cannot read: {e}") from e
        except json.JSONDecodeError as e:
            raise RuntimeError(f"{_ENV_POLICY}: invalid JSON: {e}") from e
        if not isinstance(data, dict):
            raise RuntimeError(f"{_ENV_POLICY}: root must be a JSON object")
        _policy_cache = (path, mtime_ns, data)
        return dict(data)


def policy_scan_options_error(scan_options: list[str], policy: dict[str, Any]) -> str | None:
    prefs = policy.get("disallowed_scan_option_prefixes")
    if not isinstance(prefs, list):
        return None
    for o in scan_options:
        for p in prefs:
            if not isinstance(p, str) or not p:
                continue
            if o == p or o.startswith(p):
                return (
                    f"policy file disallows scan option {o!r} "
                    f"(matched prefix {p!r}; {_ENV_POLICY})."
                )
    exact = policy.get("disallowed_scan_options_exact")
    if isinstance(exact, list):
        bad = frozenset(str(x) for x in exact if isinstance(x, str))
        for o in scan_options:
            if o in bad:
                return f"policy file disallows scan option {o!r} ({_ENV_POLICY})."
    return None


def policy_targets_error(targets: list[str], policy: dict[str, Any]) -> str | None:
    """
    If allowed_target_cidrs or allowed_hostnames is set, each target must match.
    Empty/missing lists mean this check is skipped (use MCP network_scope as usual).
    """
    cidrs_raw = policy.get("allowed_target_cidrs")
    hostset_raw = policy.get("allowed_hostnames")
    nets: list[Any] = []
    if isinstance(cidrs_raw, list) and cidrs_raw:
        for c in cidrs_raw:
            if not isinstance(c, str):
                return f"policy allowed_target_cidrs entries must be strings ({_ENV_POLICY})."
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                return f"policy has invalid CIDR {c!r} ({_ENV_POLICY})."
    hosts_ok: set[str] = set()
    if isinstance(hostset_raw, list) and hostset_raw:
        # DNS hostnames are case-insensitive; normalize so policy matches reliably.
        hosts_ok = {
            str(x).strip().lower().rstrip(".")
            for x in hostset_raw
            if isinstance(x, str) and str(x).strip()
        }
    if not nets and not hosts_ok:
        return None
    for t in targets:
        tnorm = t.strip().lower().rstrip(".")
        if tnorm in hosts_ok:
            continue
        if nets:
            ip_part = t.split("%", 1)[0].strip()
            try:
                ip_obj = ipaddress.ip_address(ip_part)
            except ValueError:
                return (
                    f"policy allows only listed hostnames or IP literals; "
                    f"cannot verify {t!r} ({_ENV_POLICY})."
                )
            if not any(ip_obj in net for net in nets):
                return f"policy: target {t!r} not in allowed_target_cidrs ({_ENV_POLICY})."
        elif hosts_ok and tnorm not in hosts_ok:
            return f"policy: target {t!r} not in allowed_hostnames ({_ENV_POLICY})."
    return None


def policy_cap_timeout(timeout_seconds: int, policy: dict[str, Any]) -> int:
    raw = policy.get("max_timeout_seconds")
    if isinstance(raw, int) and raw >= 1:
        return min(timeout_seconds, raw)
    if isinstance(raw, float) and raw >= 1.0:
        return min(timeout_seconds, int(raw))
    return timeout_seconds


def policy_check_max_targets(targets: list[str], policy: dict[str, Any]) -> str | None:
    raw = policy.get("max_targets")
    if isinstance(raw, int) and raw >= 1:
        if len(targets) > raw:
            return (
                f"policy max_targets is {raw}; got {len(targets)} "
                f"({_ENV_POLICY})."
            )
    return None
