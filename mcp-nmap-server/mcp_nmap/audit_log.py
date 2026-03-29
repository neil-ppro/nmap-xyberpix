"""Append-only NDJSON audit log for MCP tools (NMAP_MCP_AUDIT_LOG)."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

_ENV_AUDIT = "NMAP_MCP_AUDIT_LOG"
_lock = threading.Lock()


def audit_append(event: str, **fields: Any) -> None:
    path = os.environ.get(_ENV_AUDIT, "").strip()
    if not path or "\x00" in path or len(path) > 4096:
        return
    rec: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": event,
        **fields,
    }
    line = json.dumps(rec, ensure_ascii=False, default=str) + "\n"
    try:
        with _lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass
