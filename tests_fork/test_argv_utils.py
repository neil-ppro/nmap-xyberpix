"""Tests for xyberpix_gui.argv_utils (command assembly)."""

from __future__ import annotations

import pytest

from xyberpix_gui.argv_utils import (
    MAX_TOKEN_BYTES,
    ArgvAssemblyError,
    argv_preview,
    extend_argv_from_fragment,
    split_posix_argv,
    validate_argv_list,
)


def test_split_simple() -> None:
    assert split_posix_argv("a b c") == ["a", "b", "c"]


def test_split_quoted() -> None:
    assert split_posix_argv('one "two three"') == ["one", "two three"]


def test_split_rejects_nul() -> None:
    with pytest.raises(ArgvAssemblyError) as ei:
        split_posix_argv("a\x00b")
    assert "NUL" in ei.value.message


def test_split_unclosed_quote() -> None:
    with pytest.raises(ArgvAssemblyError) as ei:
        split_posix_argv('foo "bar')
    assert "quoting" in ei.value.message.lower() or "invalid" in ei.value.message.lower()


def test_extend_fragment() -> None:
    out: list[str] = ["-n"]
    extend_argv_from_fragment(out, "-p 22,443", what="Extra")
    assert out == ["-n", "-p", "22,443"]


def test_validate_argv_list_rejects_nul() -> None:
    with pytest.raises(ArgvAssemblyError):
        validate_argv_list(["ok", "bad\x00"])


def test_argv_preview_truncates() -> None:
    long_arg = "x" * 500
    prev = argv_preview("nmap", [long_arg], max_chars=80)
    assert prev.endswith("...")
    assert len(prev) == 80


def test_token_length_cap() -> None:
    huge = "a" * (MAX_TOKEN_BYTES + 1)
    with pytest.raises(ArgvAssemblyError):
        split_posix_argv(huge, what="x")
