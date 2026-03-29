# Curated NSE manifest (nmap-xyberpix)

The JSON file [NMAP-XYBERPIX-CURATED-MANIFEST.json](NMAP-XYBERPIX-CURATED-MANIFEST.json) lists **risk tier**, **SIEM-oriented notes**, and whether **`--safe-profile`** is recommended for selected scripts. It is meant for operators and automation that wrap Nmap, not for Nmap’s internal `script.db` engine.

## Risk tiers

| Tier | Meaning |
|------|---------|
| **low** | Read-mostly discovery; still requires authorization for the target. |
| **medium** | Active HTTP/API probing; may trigger IDS or application logs. |
| **high** | Intrusive or canary-style behavior; default **disabled** in MCP until explicit env + flags. |

## MCP alignment

Scripts referenced by **nmap-mcp-server** offsec presets must stay in sync with `_OFFSEC_ALLOWED_SCRIPTS` in `mcp-nmap-server/mcp_nmap/server.py`. When adding a script to a preset, update this manifest in the same change.

## Further reading

- [docs/nse-offsec-scripts.md](../nse-offsec-scripts.md) — fork offsec script documentation.
- [docs/SIEM-NDJSON-SCHEMA.md](../SIEM-NDJSON-SCHEMA.md) — SIEM `scan_start` preflight hints.
