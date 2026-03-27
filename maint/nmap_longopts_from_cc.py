"""Parse long option names from nmap.cc struct option long_options[]."""
from __future__ import annotations

from pathlib import Path


def parse_long_options_from_nmap_cc_text(text: str) -> list[str]:
    start = text.find("struct option long_options[] = {")
    if start < 0:
        raise RuntimeError("long_options[] not found in nmap.cc")
    end = text.find("{0, 0, 0, 0}", start)
    if end < 0:
        raise RuntimeError("long_options[] terminator not found in nmap.cc")
    block = text[start:end]
    names: list[str] = []
    i = 0
    while i < len(block):
        j = block.find('{"', i)
        if j < 0:
            break
        j += 2
        k = block.find('"', j)
        if k < 0:
            break
        name = block[j:k]
        i = k + 1
        if not name or not name[0].isalpha():
            continue
        if not all(c.isalnum() or c == "-" for c in name):
            continue
        names.append(name)
    return sorted(set(names))


def parse_long_options_from_nmap_cc(path: Path) -> list[str]:
    return parse_long_options_from_nmap_cc_text(
        path.read_text(encoding="utf-8", errors="replace")
    )
