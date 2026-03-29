"""Parse Nmap grepable / normal output and suggest nfuzz argv fragments (authorized use only)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

MAX_INPUT_BYTES = 8 * 1024 * 1024

# Grepable: Ports: 22/open/tcp//ssh///,80/open/tcp//http///
_GREP_PORTS_RE = re.compile(
    r"^Host:\s+(\S+)\s+.*?\s+Ports:\s*(.*?)\s*$", re.IGNORECASE | re.MULTILINE
)
_GREP_PORT_TOKEN_RE = re.compile(
    r"(\d+)/([^/]+)/([^/]*)/+([^/]*)/", re.IGNORECASE
)

# Normal: 22/tcp open  ssh
_TABLE_LINE_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+open\s+(\S*)\s*$", re.IGNORECASE | re.MULTILINE
)


@dataclass(frozen=True)
class OpenPortRow:
    host: str
    port: int
    proto: str  # tcp | udp
    service: str


def _read_capped(path: str) -> str:
    with open(path, "rb") as f:
        data = f.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"file exceeds {MAX_INPUT_BYTES} bytes")
    return data.decode("utf-8", errors="replace")


def parse_grepable_nmap(text: str) -> list[OpenPortRow]:
    out: list[OpenPortRow] = []
    for hm in _GREP_PORTS_RE.finditer(text):
        host = hm.group(1).strip()
        ports_blob = hm.group(2)
        for m in _GREP_PORT_TOKEN_RE.finditer(ports_blob):
            port_s, state, proto, svc = m.group(1), m.group(2), m.group(3), m.group(4)
            if state.lower() != "open":
                continue
            p = int(port_s)
            pr = (proto or "tcp").lower()
            if pr not in ("tcp", "udp"):
                pr = "tcp"
            out.append(OpenPortRow(host, p, pr, (svc or "").strip()))
    return out


def parse_normal_nmap_output(text: str, default_host: str) -> list[OpenPortRow]:
    """Parse 'PORT   STATE SERVICE' style table lines; host must be supplied."""
    out: list[OpenPortRow] = []
    for m in _TABLE_LINE_RE.finditer(text):
        p = int(m.group(1))
        pr = m.group(2).lower()
        svc = (m.group(3) or "").strip()
        out.append(OpenPortRow(default_host, p, pr, svc))
    return out


def parse_nmap_xml(text: str) -> list[OpenPortRow]:
    out: list[OpenPortRow] = []
    root = ET.fromstring(text)
    for host in root.findall(".//host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        ip = (addr_el.get("addr") or "").strip()
        if not ip:
            continue
        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or (state_el.get("state") or "").lower() != "open":
                continue
            proto = (port.get("protocol") or "tcp").lower()
            try:
                pno = int(port.get("port", "0"))
            except ValueError:
                continue
            if pno <= 0:
                continue
            svc_el = port.find("service")
            svc = (svc_el.get("name") if svc_el is not None else "") or ""
            out.append(OpenPortRow(ip, pno, proto, svc.strip()))
    return out


def suggest_nfuzz_argv_fragment(row: OpenPortRow) -> str:
    """Return shlex-safe single-token args joined as a string for nfuzz extra field."""
    svc = (row.service or "").lower()
    host = row.host
    if row.proto == "udp":
        return (
            f"--authorized --proto udp --dst {host} --dport {row.port} "
            f"-r 15 -c 300 -S random_byte --proto-payload-len 192"
        )
    if svc in ("http", "https", "http-proxy", "ssl/http"):
        return (
            f"--authorized --proto tcp --dst {host} --dport {row.port} "
            f"-r 12 -c 400 -S random_byte --proto-payload-len 320"
        )
    return (
        f"--authorized --proto tcp --dst {host} --dport {row.port} "
        f"-r 15 -c 350 -S bitflip --proto-payload-len 192"
    )


def load_ports_from_file(path: str, fmt: str) -> list[OpenPortRow]:
    text = _read_capped(path)
    fmt_l = fmt.lower()
    if fmt_l in ("g", "grepable", "grep"):
        return parse_grepable_nmap(text)
    if fmt_l in ("x", "xml"):
        return parse_nmap_xml(text)
    raise ValueError(f"unknown format {fmt!r} (use grepable or xml)")


def format_suggestion_lines(rows: list[OpenPortRow]) -> str:
    lines = []
    for r in rows:
        frag = suggest_nfuzz_argv_fragment(r)
        lines.append(f"# {r.host} {r.port}/{r.proto} ({r.service or 'unknown'})")
        lines.append(frag)
        lines.append("")
    return "\n".join(lines).rstrip() + ("\n" if lines else "")
