#!/bin/sh
# Fail if forbidden unbounded C string APIs appear in core Nmap sources.
# Allowed: Snprintf, Strncpy, strncat (with care), alloc_vsprintf, etc.
set -e
cd "$(dirname "$0")/.."
pat='\<sprintf[[:space:]]*\(|\<strcpy[[:space:]]*\(|[^[:alnum:]_]strcat[[:space:]]*\('
hits=$(grep -n -E "$pat" nmap.cc output.cc nse_*.cc 2>/dev/null | grep -v alloc_vsprintf || true)
if test -n "$hits"; then
  echo "Unsafe string ops found (use Snprintf/Strncpy/etc.):" >&2
  echo "$hits" >&2
  exit 1
fi
exit 0
