#!/usr/bin/env bash
# Fetch and merge a ref from the upstream Nmap remote (expect conflicts on a fork).
# Usage: maint/merge-upstream.sh <ref>
# Example: maint/merge-upstream.sh master
set -euo pipefail

REF="${1:?usage: $0 <upstream-ref e.g. master or Nmap-7.98>}"
REMOTE="${UPSTREAM_REMOTE:-upstream}"

if ! git remote get-url "$REMOTE" &>/dev/null; then
  echo "No git remote named '$REMOTE'. Add with:" >&2
  echo "  git remote add $REMOTE https://github.com/nmap/nmap.git" >&2
  exit 2
fi

git fetch "$REMOTE" "$REF"
# Works for branch names and tags (FETCH_HEAD is the fetched commit).
git merge --no-edit FETCH_HEAD

echo
echo "Merge complete. Next: resolve any conflicts, ./configure && make,"
echo "  python3 maint/check_zenmap_siem_flags.py && python3 maint/check_offsec_mcp_sync.py,"
echo "  cd mcp-nmap-server && .venv/bin/pytest tests/ -q (after pip install -e '.[dev]'),"
echo "  maint/siem_ndjson_smoketest.sh ./nmap"
echo "See docs/UPSTREAM-MERGE.md."
