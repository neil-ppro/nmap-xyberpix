"""Append-only NDJSON audit log for MCP tools (NMAP_MCP_AUDIT_LOG)."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

_ENV_AUDIT = "NMAP_MCP_AUDIT_LOG"
_lock = threading.Lock()

# Bound serialized record size (log injection / memory DoS if a client sends huge argv).
_MAX_AUDIT_STRING_CHARS = 8192
_MAX_AUDIT_LIST_ITEMS = 512
_MAX_AUDIT_DEPTH = 14
_MAX_AUDIT_JSON_BYTES = 256 * 1024


def _sanitize_audit_value(val: Any, depth: int = 0) -> Any:
    if depth > _MAX_AUDIT_DEPTH:
        return "[...]"
    if isinstance(val, str):
        if len(val) > _MAX_AUDIT_STRING_CHARS:
            return val[:_MAX_AUDIT_STRING_CHARS] + "[...]"
        return val
    if isinstance(val, dict):
        return {str(k): _sanitize_audit_value(v, depth + 1) for k, v in val.items()}
    if isinstance(val, (list, tuple)):
        out = [_sanitize_audit_value(x, depth + 1) for x in val[:_MAX_AUDIT_LIST_ITEMS]]
        if len(val) > _MAX_AUDIT_LIST_ITEMS:
            out.append("[... list truncated ...]")
        return out
    return val


def audit_append(event: str, **fields: Any) -> None:
    path = os.environ.get(_ENV_AUDIT, "").strip()
    if not path or "\x00" in path or len(path) > 4096:
        return
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    rec: dict[str, Any] = {
        "ts": ts,
        "event": event,
        **_sanitize_audit_value(fields),
    }
    line = json.dumps(rec, ensure_ascii=False, default=str) + "\n"
    if len(line.encode("utf-8")) > _MAX_AUDIT_JSON_BYTES:
        line = (
            json.dumps(
                {
                    "ts": ts,
                    "event": event,
                    "audit_oversized": True,
                    "note": "original record exceeded NMAP_MCP_AUDIT_LOG line cap",
                },
                ensure_ascii=False,
            )
            + "\n"
        )
    try:
        with _lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass
