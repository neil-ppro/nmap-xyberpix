#!/bin/sh
# Full rebuild with AddressSanitizer and/or UndefinedBehaviorSanitizer.
# Usage:
#   ./maint/build-with-sanitizers.sh              # ASan only
#   ./maint/build-with-sanitizers.sh --ubsan      # UBSan only
#   ./maint/build-with-sanitizers.sh --both       # both (may need linker support)
set -e
cd "$(dirname "$0")/.."
opts=""
case "${1:-}" in
  --ubsan) opts="--enable-ubsan" ;;
  --both)  opts="--enable-asan --enable-ubsan" ;;
  *)       opts="--enable-asan" ;;
esac
./configure $opts
make -j"${NPROC:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
