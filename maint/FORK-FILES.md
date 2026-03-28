# nmap-xyberpix patch boundary (indicative)

Paths below are **likely to conflict** or are **fork-specific**. Use this when merging upstream Nmap. It is not a complete inventory; grep for `siem_log`, `nmap-xyberpix`, `http_offsec`, and `[nmap-xyberpix]` in `CHANGELOG` for more context.

## Core C/C++ (telemetry & CLI)

- `siem_log.c`, `siem_log.h`
- `nmap.cc`, `nmap.h` (SIEM init, options, scan start/end hooks)
- `output.cc` (SIEM port/host/service/OS hooks; upstream may touch heavily)
- `nmap_opt.cc` / option tables (long options for fork-specific flags)
- `scan_adaptive.c`, `timing.cc`, `targets.cc`, `tcpip.cc`, `scan_engine.cc`, … (as listed in CHANGELOG for decoy / adaptive features)
- `service_scan.cc` (TLS fingerprint / tlsfp)
- `docs/nmap.1`, `docs/nmap.usage.txt`, `docs/refguide.xml` (if present)

## Python / MCP

- `mcp-nmap-server/` (entire package, tests, `pyproject.toml`)

## Zenmap

- `zenmap/zenmapCore/NmapOptions.py` (long-option tables, render/parse for fork flags)
- `zenmap/zenmapGUI/OptionBuilder.py`, `ProfileEditor.py`, related GUI for “SIEM & scan policy”

## NSE / libraries

- `nselib/http_offsec.lua`
- Fork-added scripts under `scripts/` (e.g. `http-openapi-map.nse`, `k8s-api-anon-audit.nse`, … — see `docs/nse-offsec-scripts.md`)

## Security & operator docs

- `docs/security/*.md`
- `docs/nse-offsec-scripts.md`
- `docs/IDS-EVASION-NMAP-XYBERPIX.md`
- `docs/SIEM-NDJSON-SCHEMA.md`
- `docs/examples/siem/README.md`
- `docs/security/SECURITY-OVERVIEW.md`
- `README-nmap-xyberpix.md`, root `README.md` (fork overview)

## Maintenance / CI

- `maint/*.py`, `maint/*.sh` (self-tests, data refresh, merge helpers)
- `maint/data/nmap-long-options-baseline.txt` (parsed from `nmap.cc`; regen with `maint/update_mcp_longopt_baseline.py`)
- `maint/data/zenmap-nmap-longopt-exceptions.txt` (nmap long opts not exposed in Zenmap `LONG_OPTIONS`)
- `.github/workflows/nmap-xyberpix-checks.yml`

## Upstream-owned but frequently merged

- `nmap-services`, `nmap-service-probes`, `nmap-os-db` (refresh via `maint/update-nmap-data.sh` when tracking upstream data)
