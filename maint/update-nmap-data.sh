#!/bin/sh
# Refresh bundled Nmap data files (services, probes, OS DB) from upstream Nmap
# sources. Run from the maint/ directory or pass DESTDIR as first argument.
# Override the base URL with NMAP_DATA_URL (default: Nmap GitHub master).

set -e
DESTDIR="${1:-..}"
BASE="${NMAP_DATA_URL:-https://raw.githubusercontent.com/nmap/nmap/master}"

echo "Fetching nmap-services, nmap-service-probes, nmap-os-db into ${DESTDIR}/"
for f in nmap-services nmap-service-probes nmap-os-db; do
  curl -fsSL "${BASE}/${f}" -o "${DESTDIR}/${f}.new"
  mv "${DESTDIR}/${f}.new" "${DESTDIR}/${f}"
done

echo "Done. Review diffs and rebuild Nmap."
