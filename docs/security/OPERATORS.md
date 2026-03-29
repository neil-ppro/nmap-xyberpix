# Operator security guide (nmap-xyberpix)

This page is the **entry point** for anyone running or deploying fork-specific features: what requires explicit acknowledgement, which environment variables gate risk, and where to read details. It does not replace upstream Nmap’s own documentation on privileges and script safety.

## Who should read what

| Role | Start here | Then |
|------|------------|------|
| **Security / governance** | This file | [SECURITY-OVERVIEW.md](SECURITY-OVERVIEW.md) |
| **MCP / AI automation** | [mcp-nmap-server/README.md](../../mcp-nmap-server/README.md) | [MCP-TARGET-ARGV-INJECTION.md](MCP-TARGET-ARGV-INJECTION.md), [MCP-SCAN-OPTIONS-POLICY-BYPASS.md](MCP-SCAN-OPTIONS-POLICY-BYPASS.md) |
| **SIEM pipelines** | [SIEM-NDJSON-SCHEMA.md](../SIEM-NDJSON-SCHEMA.md) | [examples/siem/README.md](../examples/siem/README.md) |
| **Offsec NSE** | [nse-offsec-scripts.md](../nse-offsec-scripts.md) | Script headers, `http_offsec` gates |
| **Secret scanning (ngit)** | **`ngit(1)`** | SECURITY-OVERVIEW § ngit |
| **Fuzzing (nfuzz)** | **`nfuzz(1)`** | SECURITY-OVERVIEW § nfuzz |
| **Desktop launcher** | [xyberpix-gui README](../../xyberpix-gui/README.md) | SECURITY-OVERVIEW § Xyberpix GUI |

## Acknowledgement flags (do not skip)

These tools refuse to run until the operator explicitly accepts responsibility:

- **`ngit`**: **`--authorized`** or **`NGIT_AUTHORIZED=1`**. Use only on repositories you **own** or are **explicitly authorized** to assess.
- **`nfuzz`**: **`--authorized`** or **`NFUZZ_AUTHORIZED=1`**. Raw and network modes can affect **third parties**; HTTP daemon defaults to **loopback** unless **`--http-allow-remote`**.
- **MCP non-loopback scans**: tool flags plus server env **`NMAP_MCP_ALLOW_ANY_TARGET=1`** (see MCP README).

## High-impact environment variables (quick reference)

| Variable | Component | Meaning |
|----------|-----------|---------|
| `NMAP_MCP_BINARY` | MCP | Path to `nmap` (executable file; validated). |
| `NMAP_MCP_ALLOW_ANY_TARGET` | MCP | Must be `1` for non-loopback targets when the tool requests it. |
| `NMAP_MCP_ALLOW_UNSAFE_CLI` | MCP | Must be `1` to allow NSE, `-iL`, file outputs, extra data paths, etc. |
| `NMAP_MCP_DATADIR` | MCP | Repo root with `scripts/` / `nselib/` for fork presets. |
| `NMAP_MCP_OFFSEC_INTRUSIVE` | MCP | Must be `1` for intrusive offsec presets. |
| `GITHUB_TOKEN` / `GH_TOKEN` | ngit | API rate limits and private repo access; must not contain control bytes (ngit rejects them). |
| `NGIT_AUTHORIZED` | ngit | Same role as `--authorized`. |
| `NFUZZ_AUTHORIZED` | nfuzz | Same role as `--authorized`. |
| `NFUZZ_BROWSER_CMD` / `--browser-cmd` | nfuzz | Single `execvp` token; no shell metacharacters or control bytes. |
| `NMAP_XYBERPIX_ROOT` | xyberpix-gui | Repo root hint; NUL in value is ignored. |

Full MCP table: [SECURITY-OVERVIEW.md](SECURITY-OVERVIEW.md) and the MCP README.

## Network and data boundaries

- **MCP** defaults to **loopback-only** targets unless scope and env acks are set.
- **ngit** talks to **GitHub** and runs **`git clone`**; it validates **`OWNER/NAME`** slugs and caps API response size (see CHANGELOG / SECURITY-OVERVIEW).
- **nfuzz** can send raw or stream traffic and serve HTTP; bind and browser argv are constrained (see **`nfuzz(1)`**).
- **xyberpix-gui** runs tools with **`QProcess`** (argv list, **no shell**); user “extra” text is split with bounded POSIX **`shlex`** rules ([argv_utils.py](../../xyberpix-gui/xyberpix_gui/argv_utils.py)).

## Where release notes and PoCs live

- **Fork changelog**: root [CHANGELOG](../../CHANGELOG), entries tagged **`[nmap-xyberpix]`** / **`[SIEM]`**.
- **Illustrative security PoCs**: [docs/security/](.) (e.g. MCP policy demonstrations).

## Maintenance and upstream merges

- **Merge process**: [UPSTREAM-MERGE.md](../UPSTREAM-MERGE.md)
- **Likely-touched paths**: [maint/FORK-FILES.md](../../maint/FORK-FILES.md)
- **Checklist (tests, CI, audits)**: [FORK-MAINTENANCE.md](../FORK-MAINTENANCE.md)

## Automated checks

CI workflow **nmap-xyberpix-checks** runs MCP tests, maintainer sync scripts, long-option baseline checks, SIEM smoke, **fork Python tests** under **`tests_fork/`** (ngit, argv utilities, PySide6 GUI argv checks with **`QT_QPA_PLATFORM=offscreen`**), **`pip-audit -r tests_fork/requirements-ci.txt`**, and on Ubuntu **builds `nfuzz` and runs `nfuzz --version`** after **`make`**. See [.github/workflows/nmap-xyberpix-checks.yml](../../.github/workflows/nmap-xyberpix-checks.yml).
