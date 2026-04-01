#!/usr/bin/env bash
# Fork C/C++ diff vs upstream Nmap. Requires: git remote upstream + fetch.
# See docs/security/FORK-C-CORE-SECURITY-INVENTORY.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
UPSTREAM_REF="${UPSTREAM_REF:-upstream/master}"
if ! git rev-parse --verify "$UPSTREAM_REF" >/dev/null 2>&1; then
  echo "Missing git ref: $UPSTREAM_REF" >&2
  echo "Add and fetch upstream, e.g.:" >&2
  echo "  git remote add upstream https://github.com/nmap/nmap.git" >&2
  echo "  git fetch upstream master" >&2
  echo "Override with UPSTREAM_REF=upstream/main if needed." >&2
  exit 1
fi
echo "=== Stat vs $UPSTREAM_REF ==="
git diff "$UPSTREAM_REF"...HEAD --stat -- '*.c' '*.cc' '*.h'
echo
echo "=== Files changed (C/C++/headers) ==="
git diff "$UPSTREAM_REF"...HEAD --name-only -- '*.c' '*.cc' '*.h' | sort -u
echo
echo "Full patch: git diff $UPSTREAM_REF...HEAD -- '*.c' '*.cc' '*.h'"
