#!/usr/bin/env bash
# Static grep pass for high-risk C/Lua patterns (nmap-xyberpix tree).
# Uses grep -R with --exclude-dir (BSD/GNU) so it works without huge find -exec + argv.
# See docs/security/CODE-AUDIT-C-NSE-FULL-SCAN.md
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

EXCLUDE_DIRS=(
  liblua libpcap libssh2 libz libpcre2 libpcre libdnet-stripped liblinear
  .git mcp-nmap-server xyberpix-gui zenmap nxytools ngit
)
EXCL=()
for d in "${EXCLUDE_DIRS[@]}"; do
  EXCL+=(--exclude-dir="$d")
done

scan_c_exec() {
  # Omit bare system( — English "system (" in comments causes massive false positives.
  local pat='[[:<:]]popen[[:space:]]*\(|execl\(|execlp\(|execv\(|execvp\(|CreateProcess[[:space:]]*\('
  grep -R -n -E "$pat" \
    --include='*.c' --include='*.cc' --include='*.h' \
    "${EXCL[@]}" \
    "$ROOT" 2>/dev/null || true
}

scan_c_strings() {
  # Word boundaries: avoid matching identifiers like string_pool_sprintf, free_new_targets.
  local pat='[[:<:]]strcpy[[:space:]]*\(|[[:<:]]strcat[[:space:]]*\(|[[:<:]]sprintf[[:space:]]*\(|[[:<:]]gets[[:space:]]*\('
  grep -R -n -E "$pat" \
    --include='*.c' --include='*.cc' \
    "${EXCL[@]}" \
    "$ROOT" 2>/dev/null | head -n 120 || true
}

echo "=== Repo root: $ROOT ==="
if [ "${USE_RG:-0}" = 1 ] && command -v rg >/dev/null 2>&1; then
  echo "(using ripgrep)"
  rg -n '\bsystem\s*\(|\bpopen\s*\(|execlp?\s*\(|execvp?\s*\(|CreateProcess\s*\(' \
    --glob '*.c' --glob '*.cc' --glob '*.h' \
    --glob '!liblua/**' --glob '!libpcap/**' --glob '!libssh2/**' \
    "$ROOT" 2>/dev/null | head -n 200 || true
else
  echo "(using grep -R)"
  echo
  echo "--- C/C++: process execution ---"
  scan_c_exec
  echo
  echo "--- C/C++: strcpy/strcat/sprintf/gets (first 120) ---"
  scan_c_strings
fi

echo
echo "--- NSE: loadfile (sample) ---"
grep -R -n 'loadfile[[:space:]]*(' --include='*.nse' "$ROOT/scripts" 2>/dev/null | head -n 40 || true

echo
echo "--- NSE: os.execute / io.popen in scripts/ ---"
if grep -R -l -E 'os\.execute|io\.popen' --include='*.nse' "$ROOT/scripts" 2>/dev/null | grep -q .; then
  grep -R -n -H -E 'os\.execute|io\.popen' --include='*.nse' "$ROOT/scripts" 2>/dev/null
else
  echo "(none in scripts/)"
fi

echo
echo "--- nselib: os.execute / io.popen (first 20 lines) ---"
grep -R -n -H -E 'os\.execute|io\.popen' --include='*.lua' "$ROOT/nselib" 2>/dev/null | head -n 20 || true

echo
echo "--- Third-party dirs excluded from C scan: ${EXCLUDE_DIRS[*]} ---"
echo "Done."
