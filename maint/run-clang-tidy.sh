#!/bin/sh
# Run clang-tidy on core C++ sources. Requires compile_commands.json in the
# project root (generate with Bear while building, e.g.):
#   bear --append -- make -j"$(nproc)"
set -e
cd "$(dirname "$0")/.."
if ! test -f compile_commands.json; then
  echo "Missing compile_commands.json. Generate it while building, e.g.:"
  echo "  bear --append -- make -j\"\$(nproc)\""
  exit 1
fi
set +e
clang-tidy -p . \
  nmap.cc output.cc \
  nse_db.cc nse_debug.cc nse_dnet.cc nse_fs.cc nse_libssh2.cc \
  nse_lpeg.cc nse_main.cc nse_nmaplib.cc nse_nsock.cc nse_openssl.cc \
  nse_ssl_cert.cc nse_utility.cc nse_zlib.cc \
  "$@"
status=$?
if test "$status" -ne 0; then
  echo "clang-tidy finished with status $status (warnings may be non-fatal)."
fi
exit "$status"
