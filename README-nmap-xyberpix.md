# nmap-xyberpix

This repository is **nmap-xyberpix**: upstream **Nmap** plus patches and add-ons aimed at operators, SIEM pipelines, and controlled automation (including AI agents via MCP). Licensing is unchanged from Nmap; see [Nmap Copyright and Licensing](https://nmap.org/book/man-legal.html).

## What differs from upstream Nmap

High-level additions (see [CHANGELOG](CHANGELOG) for `[nmap-xyberpix]` and `[SIEM]` entries):

| Area | Summary |
|------|---------|
| **SIEM / analytics** | `--siem-log`, `--siem-syslog`, `--siem-tag`: newline-delimited JSON events (`schema_version`, `ts`, `event`, …). Schema: [docs/SIEM-NDJSON-SCHEMA.md](docs/SIEM-NDJSON-SCHEMA.md); examples: [docs/examples/siem/README.md](docs/examples/siem/README.md). |
| **Scan policy & tuning** | Flags such as `--safe-profile`, `--ipv6-robust`, `--adaptive-rate`, `--auto-hostgroup`; decoy timing via `--decoy-stagger` / `--decoy-stagger-random` (see [docs/IDS-EVASION-NMAP-XYBERPIX.md](docs/IDS-EVASION-NMAP-XYBERPIX.md)). **`--ssh-bounce`** runs OpenSSH `-D` and relays version/NSE TCP like `--proxies` SOCKS4 (Unix; see man page). |
| **TLS / service metadata** | Optional TLS fingerprint material in service scan XML when OpenSSL is enabled. |
| **Zenmap** | Profile editor tab for SIEM and scan-policy options so saved profiles match the fork’s CLI. Install/GTK notes: [docs/ZENMAP-INSTALL.md](docs/ZENMAP-INSTALL.md). |
| **MCP server** | Python stdio server in [mcp-nmap-server/](mcp-nmap-server/) (`nmap_dry_run`, `nmap_run_scan`, offsec presets, etc.) with a default **safe mode** for options and targets. |
| **NSE (offsec-oriented)** | Additional scripts and `nselib` helpers (e.g. `http_offsec`); use only on **authorized** targets. Overview: [docs/nse-offsec-scripts.md](docs/nse-offsec-scripts.md). |
| **Developer tooling** | Optional sanitizers, clang-tidy helpers, and maint scripts under `maint/` (see CHANGELOG). |
| **nfuzz** | Optional **`nfuzz`** binary: raw IPv4 mutation from hex, **`--pcap`** (rdpcap-style), or **`--template`** (ICMP/UDP/TCP with optional IP/TCP options), **`--frag-mtu`**, and/or **`--http-daemon`** (serves new fuzzed HTML/JS per request for browser testing; loopback bind by default). **`--auto-browser`** can launch a supervised headless browser against the fuzz URL. Requires `--authorized` / `NFUZZ_AUTHORIZED=1`; raw mode usually needs root. Built by default on Unix; `./configure --without-nfuzz` to skip. See **`nfuzz(1)`** and [docs/security/SECURITY-OVERVIEW.md](docs/security/SECURITY-OVERVIEW.md). |

## Build and install

Core Nmap build matches upstream:

```bash
./configure
make
make install
```

For detailed platform notes, see the [Nmap Install Guide](https://nmap.org/book/install.html).

**MCP package** (optional; not installed by `make install`):

```bash
cd mcp-nmap-server
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m mcp_nmap   # or: nmap-mcp-server after install
```

Point `NMAP_MCP_BINARY` at your built `nmap` if it is not on `PATH`; for offsec presets that need fork scripts, set `NMAP_MCP_DATADIR` to the **repository root** (directory containing `scripts/` and `nselib/`). Details: [mcp-nmap-server/README.md](mcp-nmap-server/README.md).

## Security documentation

| Topic | Where to read |
|--------|----------------|
| **Single overview** (threat model, env vars, links) | [docs/security/SECURITY-OVERVIEW.md](docs/security/SECURITY-OVERVIEW.md) |
| **MCP** tools, presets, client config | [mcp-nmap-server/README.md](mcp-nmap-server/README.md) |
| **MCP** argv / target injection notes | [docs/security/MCP-TARGET-ARGV-INJECTION.md](docs/security/MCP-TARGET-ARGV-INJECTION.md) |
| **MCP** scan-options policy bypass write-ups | [docs/security/MCP-SCAN-OPTIONS-POLICY-BYPASS.md](docs/security/MCP-SCAN-OPTIONS-POLICY-BYPASS.md) |
| **Offsec NSE** index, script-args, MCP allowlist, maintainer checklist | [docs/nse-offsec-scripts.md](docs/nse-offsec-scripts.md) |
| **SIEM NDJSON** fields and `schema_version` policy | [docs/SIEM-NDJSON-SCHEMA.md](docs/SIEM-NDJSON-SCHEMA.md) |
| **SIEM** jq / Splunk / Elastic examples | [docs/examples/siem/README.md](docs/examples/siem/README.md) |
| **Decoy / IDS-oriented** nmap-xyberpix behavior | [docs/IDS-EVASION-NMAP-XYBERPIX.md](docs/IDS-EVASION-NMAP-XYBERPIX.md) |
| **Merging upstream** Nmap | [docs/UPSTREAM-MERGE.md](docs/UPSTREAM-MERGE.md) |
| **Fork file boundary** (merge hints) | [maint/FORK-FILES.md](maint/FORK-FILES.md) |

Illustrative PoCs live under [docs/security/](docs/security/). CI (`.github/workflows/nmap-xyberpix-checks.yml`) runs MCP **pytest on Ubuntu and Windows**, maintainer sync scripts, a **`nmap.cc` long-options baseline** (fail on new `--long-opt` until the baseline is refreshed and MCP safe mode is reviewed), and **SIEM smoke** using a built `nmap` binary passed between jobs via artifacts. **`maint/check_zenmap_siem_flags.py`** ties **Zenmap** `LONG_OPTIONS` and **`profile_editor.xml`** (SIEM tab tooltips) to the same long-option list as `nmap.cc`, modulo **`maint/data/zenmap-nmap-longopt-exceptions.txt`** for GUI omissions.

## Upstream relationship

Feature development here is intentionally layered on Nmap. When reporting bugs, confirm whether they reproduce on **vanilla Nmap**; fork-specific issues belong with this tree’s maintainers and are called out in [CHANGELOG](CHANGELOG).
