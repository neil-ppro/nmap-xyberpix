#!/usr/bin/env bash
# Run a minimal scan with --siem-log - and verify NDJSON lines include schema_version and ts.
# Usage: maint/siem_ndjson_smoketest.sh /path/to/nmap
set -euo pipefail

NMAP_BIN="${1:-./nmap}"
if [ ! -x "$NMAP_BIN" ]; then
  echo "usage: $0 /path/to/nmap" >&2
  exit 2
fi

TMP=$(mktemp)
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

set +e
"$NMAP_BIN" -sn 127.0.0.1 --siem-log - >"$TMP" 2>&1
set -e

python3 - "$TMP" <<'PY'
import json, sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="replace")
found = []
for line in text.splitlines():
    t = line.strip()
    if len(t) < 2 or not t.startswith("{") or not t.endswith("}"):
        continue
    try:
        o = json.loads(t)
    except json.JSONDecodeError:
        continue
    if not isinstance(o, dict):
        continue
    if o.get("schema_version") != 1 or "event" not in o:
        continue
    found.append(o)

if not found:
    sys.stderr.write("siem_smoketest: no SIEM NDJSON objects with schema_version=1\n")
    sys.exit(1)

for o in found:
    ts = o.get("ts")
    if not isinstance(ts, str) or not ts.endswith("Z"):
        sys.stderr.write(f"siem_smoketest: bad ts in {o!r}\n")
        sys.exit(1)

print("siem_smoketest_ok", len(found), "events")
PY
