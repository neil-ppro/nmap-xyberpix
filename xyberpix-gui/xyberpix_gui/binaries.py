"""Resolve paths to nmap, nping, ncat, nfuzz, ngit, and nxytools CLIs."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def _looks_like_xyberpix_root(anc: Path) -> bool:
    if not (anc / "mcp-nmap-server").is_dir():
        return False
    # Built tree: `nmap` may be a binary at repo root; source tree has nmap/ directory.
    n = anc / "nmap"
    return n.is_dir() or n.is_file()


def find_repo_root() -> Path | None:
    """Return nmap-xyberpix tree root (mcp-nmap-server/ + nmap dir or binary), or None."""
    env = os.environ.get("NMAP_XYBERPIX_ROOT", "").strip()
    if env:
        if "\x00" in env:
            return None
        p = Path(env).expanduser().resolve()
        return p if p.is_dir() else None
    here = Path(__file__).resolve().parent
    for anc in here.parents:
        if _looks_like_xyberpix_root(anc):
            return anc
    return None


def _repo_root() -> Path | None:
    return find_repo_root()


def _candidates(name: str) -> list[Path]:
    out: list[Path] = []
    root = _repo_root()
    if root:
        # Built binary often at repo root (e.g. ./nmap); else subdirectory (nmap/nmap).
        root_bin = root / name
        if root_bin.is_file() and os.access(root_bin, os.X_OK):
            out.append(root_bin)
        subdirs = {
            "nmap": ("nmap",),
            "nping": ("nping",),
            "ncat": ("ncat",),
            "nfuzz": ("nfuzz",),
            "ngit": ("ngit",),
            "nxy-banner": ("nxytools",),
            "nxy-dnsperm": ("nxytools",),
            "nxy-httpfuzz": ("nxytools",),
            "nxy-wsprobe": ("nxytools",),
        }
        for sub in subdirs.get(name, ()):
            for exe in (name, f"{name}.exe"):
                p = root / sub / exe
                if p.is_file() and os.access(p, os.X_OK):
                    out.append(p)
    which = shutil.which(name)
    if which:
        out.append(Path(which))
    return out


def resolve_binary(tool: str, override: str | None) -> str | None:
    if override and override.strip():
        o = override.strip()
        if "\x00" in o:
            return None
        p = Path(o).expanduser()
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        w = shutil.which(str(p))
        if w:
            return w
    for c in _candidates(tool):
        return str(c)
    return shutil.which(tool)
