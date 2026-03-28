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

import defusedxml.ElementTree as ET
from defusedxml.common import EntitiesForbidden
from mcp.server.fastmcp import FastMCP

# Characters that must not appear in any argv fragment (shell-injection hygiene
# and C argv NUL termination).
_FORBIDDEN_ARG_CHARS = frozenset("|;`$&\n\r\0")

# Optional env override for non-PATH nmap location.
_ENV_NMAP_BINARY = "NMAP_MCP_BINARY"

# When network_scope is \"any\", require this env var to be set to \"1\" (belt
# and suspenders with the MCP tool flag).
_ENV_ALLOW_ANY = "NMAP_MCP_ALLOW_ANY_TARGET"

# Allow --script, -A, -iL, arbitrary -o*/--siem-log paths, etc. Operators only.
_ENV_UNSAFE_CLI = "NMAP_MCP_ALLOW_UNSAFE_CLI"

# Optional --datadir for nmap-xyberpix tree (custom nselib/scripts without unsafe CLI).
_ENV_DATADIR = "NMAP_MCP_DATADIR"

# Belt-and-suspenders with allow_intrusive_offsec on offsec preset tools.
_ENV_OFFSEC_INTRUSIVE = "NMAP_MCP_OFFSEC_INTRUSIVE"

# MCP safe-mode: long options blocked by exact match or `--flag=value` prefix.
# Kept as module-level tables for auditability and tests (see tests/test_policy_extended.py).
_SAFE_MODE_LONG_PREFIX_BLOCKLIST: tuple[str, ...] = (
    "--resume",
    "--iR",
    "--proxies",
    "--proxy",
    "--ssh-bounce",
    "--ssh-bounce-port",
    "--sI",
)

_SAFE_MODE_LONG_BASE_BLOCKLIST: frozenset[str] = frozenset(
    {
        "--datadir",
        "--servicedb",
        "--versiondb",
        "--stylesheet",
        "--excludefile",
    }
)

_DEFAULT_TIMEOUT = 120
_MAX_TIMEOUT = 3600
_MAX_ARG_LEN = 8192

# Cap captured nmap stdout/stderr returned to MCP clients (bytes, UTF-8).
_ENV_MAX_STDOUT = "NMAP_MCP_MAX_STDOUT_BYTES"
_ENV_MAX_STDERR = "NMAP_MCP_MAX_STDERR_BYTES"
_DEFAULT_MAX_STDOUT_CAPTURE = 2 * 1024 * 1024
_DEFAULT_MAX_STDERR_CAPTURE = 512 * 1024

# nmap_parse_xml_summary limits
_MAX_XML_TEXT_BYTES = 50_000_000
_MAX_XML_HOSTS_RETURNED = 10_000


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = int(raw, 10)
        return v if v > 0 else default
    except ValueError:
        return default


def _truncate_utf8_text(s: str, max_bytes: int) -> tuple[str, bool]:
    """Return (text, truncated) with UTF-8-safe truncation."""
    if max_bytes <= 0:
        return "", True
    raw = s.encode("utf-8")
    if len(raw) <= max_bytes:
        return s, False
    cut = raw[:max_bytes]
    while cut and (cut[-1] & 0x80) and not (cut[-1] & 0x40):
        cut = cut[:-1]
    out = cut.decode("utf-8", errors="replace")
    out += "\n[... output truncated by nmap-mcp-server; raise NMAP_MCP_MAX_*_BYTES ...]"
    return out, True


def _xml_local_tag(tag: str) -> str:
    if tag.startswith("{"):
        return tag.partition("}")[2] or tag
    return tag


def _parse_nmap_xml_summary(xml_text: str) -> dict[str, Any]:
    """
    Parse Nmap -oX XML using defusedxml (no regex on untrusted XML).
    Returns {"ok": True, ...} or {"ok": False, "error": ...}.
    """
    if len(xml_text) > _MAX_XML_TEXT_BYTES:
        return {"ok": False, "error": f"xml_text too large (max {_MAX_XML_TEXT_BYTES} bytes)."}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"ok": False, "error": f"invalid XML: {e}"}
    except EntitiesForbidden as e:
        return {"ok": False, "error": f"XML entity expansion not allowed: {e}"}

    hosts_out: list[dict[str, Any]] = []
    truncated = False

    for host in root.findall(".//host"):
        if len(hosts_out) >= _MAX_XML_HOSTS_RETURNED:
            truncated = True
            break

        st_el = None
        for child in host:
            if _xml_local_tag(child.tag) == "status":
                st_el = child
                break
        up = st_el is not None and (st_el.get("state") or "").lower() == "up"

        addrs: list[dict[str, str]] = []
        hostnames: list[str] = []
        ports: list[dict[str, str]] = []

        for child in host:
            lt = _xml_local_tag(child.tag)
            if lt == "address":
                addr = child.get("addr") or ""
                atype = child.get("addrtype") or ""
                if addr:
                    addrs.append({"addr": addr, "type": atype})
            elif lt == "hostnames":
                for hn in child:
                    if _xml_local_tag(hn.tag) == "hostname":
                        name = hn.get("name")
                        if name:
                            hostnames.append(name)
            elif lt == "ports":
                for p in child:
                    if _xml_local_tag(p.tag) != "port":
                        continue
                    proto = p.get("protocol") or ""
                    portid = p.get("portid") or ""
                    state = "unknown"
                    svc = ""
                    for sub in p:
                        sl = _xml_local_tag(sub.tag)
                        if sl == "state":
                            state = (sub.get("state") or "unknown").lower()
                        elif sl == "service":
                            svc = sub.get("name") or ""
                    ports.append(
                        {
                            "port": portid,
                            "protocol": proto,
                            "state": state,
                            "service": svc,
                        }
                    )

        hosts_out.append(
            {
                "up": up,
                "addresses": addrs,
                "hostnames": hostnames,
                "ports": ports,
            }
        )

    stats: dict[str, Any] = {}
    runstats_el = None
    for el in root.iter():
        if _xml_local_tag(el.tag) == "runstats":
            runstats_el = el
            break
    if runstats_el is not None:
        for ch in runstats_el:
            cl = _xml_local_tag(ch.tag)
            if cl == "finished" and ch.get("timestr"):
                stats["finished_timestr"] = ch.get("timestr")
            elif cl == "hosts":
                try:
                    if ch.get("up") is not None:
                        stats["hosts_up"] = int(ch.get("up", "0"))
                    if ch.get("down") is not None:
                        stats["hosts_down"] = int(ch.get("down", "0"))
                except ValueError:
                    pass

    out: dict[str, Any] = {
        "ok": True,
        "hosts": hosts_out,
        "runstats": stats,
    }
    if truncated:
        out["hosts_truncated"] = True
        out["hosts_total_parsed"] = len(hosts_out)
        out["note"] = (
            f"Host list capped at {_MAX_XML_HOSTS_RETURNED}; increase not supported via tool."
        )
    return out
_MAX_ARGS = 64
_MAX_PRESET_ID_LEN = 128

# Curated nmap-xyberpix NSE scripts for MCP offsec presets (no full unsafe CLI).
_OFFSEC_ALLOWED_SCRIPTS = frozenset(
    {
        "http-openapi-map",
        "http-graphql-introspect",
        "http-jwt-probe",
        "http-ssrf-canary",
        "http-cloud-metadata-reach",
        "http-llm-proxy-leak",
        "k8s-api-anon-audit",
    }
)

_OFFSEC_PRESETS: dict[str, dict[str, Any]] = {
    "http_discovery": {
        "intrusive": False,
        "description": (
            "Version scan on common web ports with http-openapi-map, "
            "http-graphql-introspect, and http-jwt-probe (dummy JWT in preset "
            "script-args for prerule; override with care) (-oX -)."
        ),
        "options": [
            "-sV",
            "-Pn",
            "-p",
            "80,443,8080,8443",
            "--script",
            "http-openapi-map,http-graphql-introspect,http-jwt-probe",
            "--script-args",
            "http-jwt-probe.jwt=eyJhbGciOiJIUzI1NiJ9.e30.z",
            "-oX",
            "-",
        ],
    },
    "k8s_api_audit": {
        "intrusive": False,
        "description": (
            "Kubernetes-style API paths on 6443/8443/8001 with k8s-api-anon-audit (-oX -)."
        ),
        "options": [
            "-sV",
            "-Pn",
            "-p",
            "6443,8443,8001",
            "--script",
            "k8s-api-anon-audit",
            "-oX",
            "-",
        ],
    },
    "intrusive_canaries": {
        "intrusive": True,
        "description": (
            "Intrusive: http-ssrf-canary, http-cloud-metadata-reach, "
            "http-llm-proxy-leak (requires script unsafe=1 args). Requires "
            f"{_ENV_OFFSEC_INTRUSIVE}=1 and allow_intrusive_offsec=true."
        ),
        "options": [
            "-sV",
            "-Pn",
            "-p",
            "80,443,8080,8443",
            "--script",
            "http-ssrf-canary,http-cloud-metadata-reach,http-llm-proxy-leak",
            "--script-args",
            "http-ssrf-canary.unsafe=1,http-cloud-metadata-reach.unsafe=1,"
            "http-llm-proxy-leak.unsafe=1",
            "-oX",
            "-",
        ],
    },
}


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


def _unsafe_cli_allowed() -> bool:
    return os.environ.get(_ENV_UNSAFE_CLI, "").strip() == "1"


def _policy_long_o_output_error(
    o: str, scan_options: list[str], i: int, n: int
) -> tuple[str | None, int | None]:
    """
    Apply the same rules as short -oN/-oG/... for long --oN/--oG/... forms.
    Returns (None, None) if ``o`` is not a long --o* output option.
    Returns (error_message, None) on policy violation.
    Returns ("", new_i) on success (stdout only); caller must set i = new_i.
    """
    if not (len(o) >= 4 and o.startswith("--o") and o[3] in "NGXSAMH"):
        return None, None
    kind = o[3]
    if kind in "AH":
        return (
            f"--o{kind} is disabled in safe mode; set {_ENV_UNSAFE_CLI}=1.",
            None,
        )
    suffix = o[4:]
    out: str
    step = 1
    if suffix.startswith("="):
        out = suffix[1:]
    elif suffix == "":
        if i + 1 >= n:
            return (
                f"--o{kind} requires a filename (use - for stdout).",
                None,
            )
        out = scan_options[i + 1]
        step = 2
    else:
        out = suffix
    if out != "-":
        return (
            "in safe mode only stdout output is allowed "
            f"for --o{kind} (-); set {_ENV_UNSAFE_CLI}=1 for files.",
            None,
        )
    return "", i + step


def _policy_short_o_output_error(
    o: str, scan_options: list[str], i: int, n: int
) -> tuple[str | None, int | None]:
    """
    Enforce safe-mode rules for short -oN/-oG/-oX/... forms.
    Returns (error, None) on violation, (None, new_i) when this token was handled,
    (None, None) when ``o`` is not a relevant -o* output option.
    """
    if not (len(o) >= 3 and o.startswith("-o") and o[2] in "NGXSAMH"):
        return None, None
    kind = o[2]
    if kind in "AH":
        return f"-o{kind} is disabled in safe mode; set {_ENV_UNSAFE_CLI}=1.", None
    rest = o[3:]
    if rest == "":
        if i + 1 >= n:
            return f"{o[:3]} requires a filename (use - for stdout).", None
        out = scan_options[i + 1]
        if out != "-":
            return (
                "in safe mode only stdout output is allowed "
                f"({o[:3]} -); set {_ENV_UNSAFE_CLI}=1 for files.",
                None,
            )
        return None, i + 2
    if rest.startswith("="):
        out = rest[1:]
        if out != "-":
            return (
                "in safe mode only stdout output is allowed "
                f"({o[:3]}=-); set {_ENV_UNSAFE_CLI}=1 for files.",
                None,
            )
        return None, i + 1
    if rest != "-":
        return (
            "in safe mode only stdout output is allowed "
            f"({o[:3]}-); set {_ENV_UNSAFE_CLI}=1 for files.",
            None,
        )
    return None, i + 1


def _policy_long_option_safe_mode(
    o: str, scan_options: list[str], i: int, n: int
) -> tuple[str | None, int]:
    """
    Handle one ``--long-option`` token under MCP safe mode.
    Returns (error_message, _) on violation, or (None, next_index) on success.
    """
    if o.startswith("--script"):
        return (
            f"script options are disabled by default; set "
            f"{_ENV_UNSAFE_CLI}=1 on the server to allow them.",
            i,
        )

    o_sub, new_i = _policy_long_o_output_error(o, scan_options, i, n)
    # Success is ("", new_i); errors are (message, None). Plain (None, None) means not an --o* output opt.
    if o_sub:
        return o_sub, i
    if new_i is not None:
        return None, new_i

    if o == "--iL" or o.startswith("--iL="):
        return (
            "--iL is disabled in safe mode (arbitrary file read); "
            f"set {_ENV_UNSAFE_CLI}=1 or use the targets parameter.",
            i,
        )

    for bl in _SAFE_MODE_LONG_PREFIX_BLOCKLIST:
        if o == bl or o.startswith(bl + "="):
            return (
                f"{bl} is disabled in MCP safe mode (file read, random "
                f"targets, proxying, or idle scan); set {_ENV_UNSAFE_CLI}=1.",
                i,
            )

    base = o.split("=", 1)[0]
    if base in _SAFE_MODE_LONG_BASE_BLOCKLIST or any(
        o == x or o.startswith(x + "=") for x in _SAFE_MODE_LONG_BASE_BLOCKLIST
    ):
        return (
            f"{base} is disabled by default; set {_ENV_UNSAFE_CLI}=1 to allow.",
            i,
        )

    if base == "--siem-log":
        val = o.split("=", 1)[1] if "=" in o else None
        idx_after_val = i
        if val is None:
            if i + 1 >= n:
                return "--siem-log requires a value.", i
            val = scan_options[i + 1]
            idx_after_val = i + 1
        if val != "-":
            return (
                "only --siem-log - (stdout) is allowed in safe mode; "
                f"set {_ENV_UNSAFE_CLI}=1 for file paths.",
                i,
            )
        return None, idx_after_val + 1

    if base == "--append-output":
        return (
            f"--append-output is disabled in safe mode; set {_ENV_UNSAFE_CLI}=1.",
            i,
        )

    return None, i + 1


def _scan_options_policy_error(scan_options: list[str]) -> str | None:
    """
    Reject scan flags that enable arbitrary code (NSE), arbitrary file reads,
    or arbitrary file writes unless NMAP_MCP_ALLOW_UNSAFE_CLI=1.
    Targets must be passed only via the tool's targets parameter (no '--' in
    scan_options).
    """
    if _unsafe_cli_allowed():
        return None

    n = len(scan_options)
    i = 0
    while i < n:
        o = scan_options[i]

        if o == "--":
            return (
                "scan_options must not contain '--'; pass targets only via "
                "the targets parameter."
            )

        if o.startswith("--"):
            err, i = _policy_long_option_safe_mode(o, scan_options, i, n)
            if err:
                return err
            continue

        if o == "-iL" or o.startswith("-iL="):
            return (
                "-iL is disabled in safe mode (arbitrary file read); "
                f"set {_ENV_UNSAFE_CLI}=1 or use the targets parameter."
            )
        if o.startswith("-iR"):
            return (
                "-iR (random targets) is disabled in MCP safe mode "
                f"(bypasses target allowlisting); set {_ENV_UNSAFE_CLI}=1."
            )
        if o == "-A":
            return (
                "-A is disabled in safe mode (runs NSE); "
                f"set {_ENV_UNSAFE_CLI}=1 to allow."
            )
        if o.startswith("-s") and len(o) > 2:
            if "C" in o[2:]:
                return (
                    "-sC (script scan) is disabled in safe mode; "
                    f"set {_ENV_UNSAFE_CLI}=1 to allow."
                )

        so_err, new_i = _policy_short_o_output_error(o, scan_options, i, n)
        if so_err is not None:
            return so_err
        if new_i is not None:
            i = new_i
            continue

        i += 1

    return None


_PORT_SPEC_RE = re.compile(r"^[\d,\-TU:*/]+$")


def _offsec_datadir_prefix() -> list[str]:
    raw = os.environ.get(_ENV_DATADIR, "").strip()
    if not raw:
        return []
    _validate_argv_fragment(raw, label=_ENV_DATADIR)
    p = os.path.realpath(raw)
    if not os.path.isdir(p):
        raise ValueError(
            f"{_ENV_DATADIR} must be an existing directory (resolved to {p!r})."
        )
    return ["--datadir", p]


def _validate_offsec_extra_scan_options(scan_options: list[str]) -> str | None:
    """Allow only a narrow set of tuning flags (no --script, -o*, -A, etc.)."""
    n = len(scan_options)
    i = 0
    while i < n:
        o = scan_options[i]
        if o in ("-Pn", "-n", "--open", "-sV", "-sT", "-sS"):
            i += 1
            continue
        if re.fullmatch(r"-T[0-5]", o):
            i += 1
            continue
        if o.startswith("--max-retries"):
            if "=" in o:
                val = o.split("=", 1)[1]
            else:
                if i + 1 >= n:
                    return "--max-retries requires a value."
                val = scan_options[i + 1]
                i += 1
            if not val.isdigit():
                return "--max-retries value must be digits only."
            i += 1
            continue
        if o.startswith("-p"):
            spec: str
            if o == "-p":
                if i + 1 >= n:
                    return "-p requires a port specification."
                spec = scan_options[i + 1]
                i += 2
            else:
                spec = o[2:].lstrip("=")
                if not spec:
                    return "-p requires a port specification."
                i += 1
            if len(spec) > 512 or not _PORT_SPEC_RE.match(spec):
                return "Invalid -p port specification in extra_scan_options."
            continue
        return (
            f"offsec extra_scan_options allows only -p, -Pn, -n, --open, "
            f"-sV/-sT/-sS, -T0..-T5, --max-retries; disallowed: {o!r}"
        )
    return None


def _offsec_intrusive_ok(
    preset: dict[str, Any], *, allow_intrusive_offsec: bool
) -> tuple[bool, str]:
    if not preset.get("intrusive"):
        return True, ""
    env_ok = os.environ.get(_ENV_OFFSEC_INTRUSIVE, "").strip() == "1"
    if allow_intrusive_offsec and env_ok:
        return True, ""
    return (
        False,
        f'Preset is intrusive; set allow_intrusive_offsec=true and server env '
        f"{_ENV_OFFSEC_INTRUSIVE}=1.",
    )


def _offsec_verify_preset_script_list(options: list[str]) -> str | None:
    """Ensure built-in preset --script values use only allowlisted NSE names."""
    i = 0
    n = len(options)
    while i < n:
        o = options[i]
        if o == "--script":
            if i + 1 >= n:
                return "preset definition: --script missing value"
            raw = options[i + 1]
            i += 2
        elif o.startswith("--script="):
            raw = o.split("=", 1)[1]
            i += 1
        else:
            i += 1
            continue
        for part in raw.split(","):
            name = part.strip()
            if not name:
                continue
            if name not in _OFFSEC_ALLOWED_SCRIPTS:
                return f"preset references disallowed script {name!r}"
    return None


def _validate_offsec_preset_id(preset_id: str) -> str | None:
    try:
        _validate_argv_fragment(preset_id, label="preset_id")
    except ValueError as e:
        return str(e)
    if len(preset_id) > _MAX_PRESET_ID_LEN:
        return f"preset_id exceeds maximum length ({_MAX_PRESET_ID_LEN})."
    return None


def _offsec_build_scan_argv(
    preset_id: str,
    extra_scan_options: list[str],
    *,
    allow_intrusive_offsec: bool,
) -> tuple[list[str] | None, str | None]:
    pid_err = _validate_offsec_preset_id(preset_id)
    if pid_err:
        return None, pid_err
    preset = _OFFSEC_PRESETS.get(preset_id)
    if not preset:
        ids = ", ".join(sorted(_OFFSEC_PRESETS))
        return None, f"Unknown preset_id {preset_id!r}. Known: {ids}"

    ok_i, err_i = _offsec_intrusive_ok(preset, allow_intrusive_offsec=allow_intrusive_offsec)
    if not ok_i:
        return None, err_i

    pol_extra = _validate_offsec_extra_scan_options(extra_scan_options)
    if pol_extra:
        return None, pol_extra

    preset_opts = list(preset["options"])
    bad_scripts = _offsec_verify_preset_script_list(preset_opts)
    if bad_scripts:
        return None, bad_scripts

    try:
        dd = _offsec_datadir_prefix()
    except ValueError as e:
        return None, str(e)

    scan_options = dd + preset_opts + list(extra_scan_options)
    try:
        _validate_scan_options(scan_options)
    except ValueError as e:
        return None, str(e)

    return scan_options, None


def _validate_target_entry(s: str, *, label: str) -> None:
    """
    Targets are appended after scan_options. Nmap uses getopt_long_only and
    continues to parse arguments that look like options even after real targets,
    so a value like '-oN' or '--script' is treated as a flag, not a hostname
    (argument injection / policy bypass). Reject any target that could be
    mistaken for an option or a Unicode-dash variant Nmap rejects.
    """
    _validate_argv_fragment(s, label=label)
    t = s.strip()
    if not t:
        raise ValueError(f"{label} must not be empty or whitespace-only.")
    if t == "--":
        raise ValueError(f'{label} must not be "--".')
    if t[0] in "-\u2010\u2011\u2012\u2013\u2014\u2015":
        raise ValueError(
            f"{label} must not start with '-' or a Unicode dash; "
            "Nmap would parse it as a CLI option (argument injection)."
        )
    # Match nmap.cc preliminary check for UTF-8 dash (U+2010..U+2015).
    b0 = ord(t[0])
    if b0 == 0xE2 and len(t) >= 3:
        b1, b2 = ord(t[1]), ord(t[2])
        if b1 == 0x80 and 0x90 <= b2 <= 0x95:
            raise ValueError(
                f"{label} contains an unparseable Unicode dash (use ASCII '-')."
            )


def _validate_targets(targets: list[str]) -> None:
    if not targets:
        raise ValueError("At least one target is required.")
    if len(targets) > _MAX_ARGS:
        raise ValueError(f"Too many targets (max {_MAX_ARGS}).")
    for i, t in enumerate(targets):
        _validate_target_entry(t, label=f"targets[{i}]")


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
    max_out = _env_int(_ENV_MAX_STDOUT, _DEFAULT_MAX_STDOUT_CAPTURE)
    max_err = _env_int(_ENV_MAX_STDERR, _DEFAULT_MAX_STDERR_CAPTURE)
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
    out, tout = _truncate_utf8_text(proc.stdout or "", max_out)
    err, terr = _truncate_utf8_text(proc.stderr or "", max_err)
    result: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": out,
        "stderr": err,
    }
    if tout:
        result["stdout_truncated"] = True
    if terr:
        result["stderr_truncated"] = True
    return result


mcp = FastMCP(
    "nmap",
    instructions=(
        "This server runs the Nmap security scanner. Prefer nmap_version and "
        "nmap_help before scanning. Use nmap_dry_run to validate commands. "
        "Default scans are restricted to loopback targets; wider scans require "
        "network_scope=any, i_acknowledge_network_scan_risk=true, and server env "
        f"{_ENV_ALLOW_ANY}=1. Never pass shell metacharacters in arguments. "
        "By default, scan_options cannot use NSE (--script, -A, -sC), -iL, "
        "arbitrary file outputs (-oA, -oN file, …), or most --datadir-style "
        f"flags; set {_ENV_UNSAFE_CLI}=1 on the server to allow the full CLI. "
        "Curated nmap-xyberpix offsec presets (nmap_offsec_*) may run a fixed "
        f"allowlisted --script set without unsafe CLI when {_ENV_DATADIR} points "
        "at an nmap-xyberpix source tree (or install includes those scripts)."
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

    Safe mode blocks NSE, -iL, non-stdout -o*, etc.; see server env
    NMAP_MCP_ALLOW_UNSAFE_CLI.
    """
    try:
        _validate_scan_options(scan_options)
        _validate_targets(targets)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    pol = _scan_options_policy_error(scan_options)
    if pol:
        return {"ok": False, "error": pol}

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

    Safe mode blocks NSE (--script, -A, -sC), -iL, file-based -o*/--siem-log,
    and similar; set server env NMAP_MCP_ALLOW_UNSAFE_CLI=1 to allow the full
    Nmap CLI (operators only).
    """
    try:
        _validate_scan_options(scan_options)
        _validate_targets(targets)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    pol = _scan_options_policy_error(scan_options)
    if pol:
        return {"ok": False, "error": pol}

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
def nmap_offsec_list_presets() -> dict[str, Any]:
    """List built-in nmap-xyberpix offensive-research scan presets (allowlisted NSE)."""
    presets = []
    for pid in sorted(_OFFSEC_PRESETS):
        spec = _OFFSEC_PRESETS[pid]
        presets.append(
            {
                "id": pid,
                "intrusive": bool(spec.get("intrusive")),
                "description": spec.get("description", ""),
            }
        )
    return {
        "ok": True,
        "presets": presets,
        "note": (
            f"Use nmap_offsec_dry_run / nmap_offsec_run_scan. Set {_ENV_DATADIR} "
            "to the nmap-xyberpix tree so Nmap loads fork scripts and nselib."
        ),
    }


@mcp.tool()
def nmap_offsec_dry_run(
    preset_id: str,
    targets: list[str],
    network_scope: str = "loopback_only",
    i_acknowledge_network_scan_risk: bool = False,
    allow_intrusive_offsec: bool = False,
    extra_scan_options: list[str] | None = None,
) -> dict[str, Any]:
    """
    Like nmap_dry_run but uses a curated offsec preset (allowlisted --script only).

    Intrusive presets require allow_intrusive_offsec=true and server env
    NMAP_MCP_OFFSEC_INTRUSIVE=1. Optional NMAP_MCP_DATADIR selects the nmap-xyberpix
    data directory (scripts + nselib).

    extra_scan_options: only -p, -Pn, -n, --open, -sV/-sT/-sS, -T0..-T5,
    --max-retries (numeric).
    """
    extras = list(extra_scan_options or [])
    scan_options, err = _offsec_build_scan_argv(
        preset_id,
        extras,
        allow_intrusive_offsec=allow_intrusive_offsec,
    )
    if err:
        return {"ok": False, "error": err}
    try:
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
    argv = [binary] + scan_options + list(targets)
    return {"ok": True, "argv": argv, "note": "Command not executed."}


@mcp.tool()
def nmap_offsec_run_scan(
    preset_id: str,
    targets: list[str],
    network_scope: str = "loopback_only",
    i_acknowledge_network_scan_risk: bool = False,
    allow_intrusive_offsec: bool = False,
    extra_scan_options: list[str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Run Nmap with a curated nmap-xyberpix offsec preset (fixed allowlisted scripts).

    See nmap_offsec_dry_run for policy. Output includes XML on stdout (-oX -).
    """
    extras = list(extra_scan_options or [])
    scan_options, err = _offsec_build_scan_argv(
        preset_id,
        extras,
        allow_intrusive_offsec=allow_intrusive_offsec,
    )
    if err:
        return {"ok": False, "error": err}
    try:
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
    argv = [binary] + scan_options + list(targets)
    out = _run_nmap(argv, timeout=timeout_seconds)
    out["argv"] = argv
    return out


@mcp.tool()
def nmap_parse_xml_summary(xml_text: str) -> dict[str, Any]:
    """
    Parse Nmap XML from -oX - and return a compact JSON-friendly summary
    (hosts, addresses, ports with state/service, run stats if present).

    Uses defusedxml (no regex) for safer parsing of untrusted XML. Very large
    scans may set ``hosts_truncated`` when more than 10,000 ``<host>`` elements
    are present.
    """
    return _parse_nmap_xml_summary(xml_text)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
