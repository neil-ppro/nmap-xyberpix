"""Safe assembly of argv lists for QProcess (no shell): bounded POSIX shlex splits."""

from __future__ import annotations

import shlex

# Limits for user-typed "extra" / targets strings (DoS and accident guardrails).
MAX_USER_FRAGMENT_BYTES = 128 * 1024
MAX_TOKENS_PER_FRAGMENT = 512
MAX_TOKEN_BYTES = 64 * 1024


class ArgvAssemblyError(ValueError):
    """Invalid or unsafe input for POSIX-style argv splitting."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _utf8_len(s: str) -> int:
    return len(s.encode("utf-8"))


def split_posix_argv(fragment: str, *, what: str = "input") -> list[str]:
    """
    Split one user field using POSIX shell-like rules (same as typical CLI pasting).
    No NUL bytes; bounded size and token count. Raises ArgvAssemblyError on failure.
    """
    if "\x00" in fragment:
        raise ArgvAssemblyError(f"{what}: NUL bytes are not allowed.")
    if _utf8_len(fragment) > MAX_USER_FRAGMENT_BYTES:
        raise ArgvAssemblyError(
            f"{what}: text too long (max {MAX_USER_FRAGMENT_BYTES} UTF-8 bytes)."
        )
    try:
        parts = shlex.split(fragment, posix=True, comments=False)
    except ValueError as e:
        raise ArgvAssemblyError(f"{what}: invalid quoting — {e}") from e
    if len(parts) > MAX_TOKENS_PER_FRAGMENT:
        raise ArgvAssemblyError(
            f"{what}: too many tokens after splitting (max {MAX_TOKENS_PER_FRAGMENT})."
        )
    for i, p in enumerate(parts):
        if "\x00" in p:
            raise ArgvAssemblyError(f"{what}: token {i + 1} contains NUL.")
        if _utf8_len(p) > MAX_TOKEN_BYTES:
            raise ArgvAssemblyError(
                f"{what}: token {i + 1} too long (max {MAX_TOKEN_BYTES} UTF-8 bytes)."
            )
    return parts


def extend_argv_from_fragment(dest: list[str], fragment: str, *, what: str) -> None:
    """Append split_posix_argv(fragment) to dest."""
    dest.extend(split_posix_argv(fragment, what=what))


def validate_argv_list(argv: list[str], *, what: str = "arguments") -> None:
    """Defense in depth before QProcess: no NUL, bounded token size."""
    for i, a in enumerate(argv):
        if "\x00" in a:
            raise ArgvAssemblyError(f"{what}: argument {i + 1} contains NUL.")
        if _utf8_len(a) > MAX_TOKEN_BYTES:
            raise ArgvAssemblyError(
                f"{what}: argument {i + 1} too long (max {MAX_TOKEN_BYTES} UTF-8 bytes)."
            )


def argv_preview(program: str, argv: list[str], *, max_chars: int = 600) -> str:
    """Single-line preview safe for UI labels (exact argv via shlex.join, truncated)."""
    line = shlex.join([program, *argv])
    if len(line) <= max_chars:
        return line
    return line[: max_chars - 3] + "..."
