"""Tests for xyberpix_gui.binaries (path resolution)."""

from __future__ import annotations

from xyberpix_gui.binaries import resolve_binary


def test_resolve_binary_rejects_nul_override() -> None:
    assert resolve_binary("nmap", "foo\x00bar") is None
