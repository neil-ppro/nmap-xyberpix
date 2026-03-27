#!/usr/bin/env python3
"""
Model Context Protocol (stdio) server for Nmap.

Exposes read-only introspection and controlled scan execution. Scans can touch
live networks; default policy only permits loopback targets unless the caller
explicitly acknowledges risk and sets network_scope to \"any\".
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from typing import Any

from mcp.server.fastmcp import FastMCP

# Characters that must not appear in any argv fragment (shell-injection hygiene).
_FORBIDDEN_ARG_CHARS = frozenset("|;`$&\n\r")

# Optional env override for non-PATH nmap location.
_ENV_NMAP_BINARY = "NMAP_MCP_BINARY"

# When network_scope is \"any\", require this env var to be set to \"1\" (belt
# and suspenders with the MCP tool flag).
_ENV_ALLOW_ANY = "NMAP_MCP_ALLOW_ANY_TARGET"

_DEFAULT_TIMEOUT = 120
_MAX_TIMEOUT = 3600
_MAX_ARG_LEN = 8192
_MAX_ARGS = 64


def _nmap_binary() -> str:
    explicit = os.environ.get(_ENV_NMAP_BINARY, "").strip()
    if explicit:
        return explicit
    found = shutil.which("nmap")
    if not found:
        raise RuntimeError(
            "nmap executable not found in PATH. Install Nmap or set "
            f"{_ENV_NMAP_BINARY} to the full path."
        )
    return found


def _validate_argv_fragment(s: str, *, label: str) -> None:
    if len(s) > _MAX_ARG_LEN:
        raise ValueError(f"{label} exceeds maximum length ({_MAX_ARG_LEN}).")
    if any(ch in s for ch in _FORBIDDEN_ARG_CHARS):
        raise ValueError(
            f"{label} contains forbidden characters "
            "(no shell metacharacters or newlines)."
        )


def _validate_scan_options(scan_options: list[str]) -> None:
    if len(scan_options) > _MAX_ARGS:
        raise ValueError(f"Too many scan_options (max {_MAX_ARGS}).")
    for i, a in enumerate(scan_options):
        _validate_argv_fragment(a, label=f"scan_options[{i}]")


def _validate_targets(targets: list[str]) -> None:
    if not targets:
        raise ValueError("At least one target is required.")
    if len(targets) > _MAX_ARGS:
        raise ValueError(f"Too many targets (max {_MAX_ARGS}).")
    for i, t in enumerate(targets):
        _validate_argv_fragment(t, label=f"targets[{i}]")


def _is_loopback_target(spec: str) -> bool:
    s = spec.strip()
    if not s:
        return False
    if s.lower() == "localhost":
        return True
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return False
        if net.prefixlen == net.max_prefixlen:
            return net.network_address.is_loopback
        return net == ipaddress.ip_network("127.0.0.0/8") or net == ipaddress.ip_network(
            "::1/128"
        )
    try:
        ip = ipaddress.ip_address(s.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_loopback


def _targets_allowed_for_scope(
    targets: list[str], network_scope: str
) -> tuple[bool, str]:
    if network_scope == "any":
        if os.environ.get(_ENV_ALLOW_ANY, "").strip() != "1":
            return (
                False,
                f'network_scope \"any\" requires environment variable '
                f"{_ENV_ALLOW_ANY}=1 on the MCP server process.",
            )
        return True, ""
    if network_scope != "loopback_only":
        return False, 'network_scope must be \"loopback_only\" or \"any\".'
    bad = [t for t in targets if not _is_loopback_target(t)]
    if bad:
        return (
            False,
            "loopback_only scope: only localhost, 127.0.0.0/8, and ::1 "
            f"targets are allowed. Not allowed: {bad!r}",
        )
    return True, ""


def _run_nmap(argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"nmap exceeded timeout ({timeout}s).",
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
    except OSError as e:
        return {
            "ok": False,
            "error": f"failed to execute nmap: {e}",
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


mcp = FastMCP(
    "nmap",
    instructions=(
        "This server runs the Nmap security scanner. Prefer nmap_version and "
        "nmap_help before scanning. Use nmap_dry_run to validate commands. "
        "Default scans are restricted to loopback targets; wider scans require "
        "network_scope=any, i_acknowledge_network_scan_risk=true, and server env "
        f"{_ENV_ALLOW_ANY}=1. Never pass shell metacharacters in arguments."
    ),
)


@mcp.tool()
def nmap_version() -> dict[str, Any]:
    """Return Nmap version and build line from `nmap --version`."""
    binary = _nmap_binary()
    return _run_nmap([binary, "--version"], timeout=30)


@mcp.tool()
def nmap_help() -> dict[str, Any]:
    """Return Nmap help text from `nmap --help` (may be long)."""
    binary = _nmap_binary()
    return _run_nmap([binary, "--help"], timeout=60)


@mcp.tool()
def nmap_dry_run(
    scan_options: list[str],
    targets: list[str],
    network_scope: str = "loopback_only",
    i_acknowledge_network_scan_risk: bool = False,
) -> dict[str, Any]:
    """
    Validate targets and options and return the argv that would be executed,
    without running Nmap.

    network_scope: \"loopback_only\" (default) or \"any\" (requires env
    NMAP_MCP_ALLOW_ANY_TARGET=1 and i_acknowledge_network_scan_risk=true).
    """
    try:
        _validate_scan_options(scan_options)
        _validate_targets(targets)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    if network_scope == "any" and not i_acknowledge_network_scan_risk:
        return {
            "ok": False,
            "error": "network_scope \"any\" requires i_acknowledge_network_scan_risk=true.",
        }

    ok_scope, scope_err = _targets_allowed_for_scope(targets, network_scope)
    if not ok_scope:
        return {"ok": False, "error": scope_err}

    binary = _nmap_binary()
    argv = [binary] + list(scan_options) + list(targets)
    return {"ok": True, "argv": argv, "note": "Command not executed."}


@mcp.tool()
def nmap_run_scan(
    scan_options: list[str],
    targets: list[str],
    network_scope: str = "loopback_only",
    i_acknowledge_network_scan_risk: bool = False,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Run Nmap with explicit argv-style scan_options followed by targets.

    Uses subprocess with a list (no shell). Default policy allows only
    loopback targets. For arbitrary hosts/networks set network_scope to \"any\",
    pass i_acknowledge_network_scan_risk=true, and start the server with
    NMAP_MCP_ALLOW_ANY_TARGET=1.

    Recommended: include -oX - (or -oG -) in scan_options to capture machine-
    readable output in stdout for the agent.
    """
    try:
        _validate_scan_options(scan_options)
        _validate_targets(targets)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    if timeout_seconds < 1 or timeout_seconds > _MAX_TIMEOUT:
        return {
            "ok": False,
            "error": f"timeout_seconds must be 1..{_MAX_TIMEOUT}.",
        }

    if network_scope == "any" and not i_acknowledge_network_scan_risk:
        return {
            "ok": False,
            "error": "network_scope \"any\" requires i_acknowledge_network_scan_risk=true.",
        }

    ok_scope, scope_err = _targets_allowed_for_scope(targets, network_scope)
    if not ok_scope:
        return {"ok": False, "error": scope_err}

    binary = _nmap_binary()
    argv = [binary] + list(scan_options) + list(targets)
    out = _run_nmap(argv, timeout=timeout_seconds)
    out["argv"] = argv
    return out


@mcp.tool()
def nmap_parse_xml_summary(xml_text: str) -> dict[str, Any]:
    """
    Parse Nmap XML from -oX - and return a compact JSON-friendly summary
    (hosts, addresses, ports with state/service, run stats if present).
    """
    # Avoid heavy deps: regex-based extraction is enough for agent summaries.
    if len(xml_text) > 50_000_000:
        return {"ok": False, "error": "xml_text too large (max 50MB)."}

    hosts: list[dict[str, Any]] = []
    for hm in re.finditer(
        r"<host\b[^>]*>(.*?)</host>",
        xml_text,
        flags=re.DOTALL | re.IGNORECASE,
    ):
        block = hm.group(1)
        up = bool(re.search(r'<status[^>]+state="up"', block, re.I))
        addrs = re.findall(
            r'<address\b[^>]*addr="([^"]+)"[^>]*addrtype="([^"]+)"', block, re.I
        )
        hostnames = re.findall(r"<hostname\b[^>]*name=\"([^\"]+)\"", block, re.I)
        ports: list[dict[str, str]] = []
        for pm in re.finditer(
            r'<port\b[^>]*protocol="(\w+)"[^>]*portid="(\d+)"[^>]*>(.*?)</port>',
            block,
            flags=re.DOTALL | re.I,
        ):
            proto, portid, pblock = pm.group(1), pm.group(2), pm.group(3)
            sm = re.search(r'<state\b[^>]*state="(\w+)"', pblock, re.I)
            state = sm.group(1) if sm else "unknown"
            sv = re.search(
                r'<service\b[^>]*name="([^"]*)"', pblock, re.I
            )
            svc = sv.group(1) if sv else ""
            ports.append(
                {
                    "port": portid,
                    "protocol": proto,
                    "state": state,
                    "service": svc,
                }
            )
        hosts.append(
            {
                "up": up,
                "addresses": [{"addr": a, "type": t} for a, t in addrs],
                "hostnames": hostnames,
                "ports": ports,
            }
        )

    stats = {}
    sm = re.search(
        r'<runstats>.*?<finished\b[^>]*timestr="([^"]*)"[^>]*/>',
        xml_text,
        flags=re.DOTALL | re.I,
    )
    if sm:
        stats["finished_timestr"] = sm.group(1)
    sm = re.search(r'<hosts\b[^>]*up="(\d+)"[^>]*down="(\d+)"', xml_text, re.I)
    if sm:
        stats["hosts_up"] = int(sm.group(1))
        stats["hosts_down"] = int(sm.group(2))

    return {"ok": True, "hosts": hosts, "runstats": stats}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
