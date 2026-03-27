# Nmap MCP server

A [Model Context Protocol](https://modelcontextprotocol.io/) (stdio) server that lets AI agents run **Nmap** safely: version/help introspection, command validation (`nmap_dry_run`), execution (`nmap_run_scan`), a small XML summarizer (`nmap_parse_xml_summary`), and **curated nmap-ppro offsec presets** (`nmap_offsec_*`) that run a fixed allowlisted `--script` set without enabling the full unsafe CLI.

This package lives in the **nmap-ppro** tree and is **not** part of the core Nmap install; install it when you want MCP integration.

## Requirements

- Python 3.10+
- `nmap` on `PATH` (or set `NMAP_MCP_BINARY` to the executable path)
- `pip install -e .` or `pip install .` from this directory (pulls in the `mcp` PyPI package)

## Run (stdio)

```bash
cd mcp-nmap-server
python3 -m mcp_nmap
# or, after install:
nmap-mcp-server
```

## Cursor / Claude Desktop–style config

Point your MCP client at the interpreter and module:

```json
{
  "mcpServers": {
    "nmap": {
      "command": "python3",
      "args": ["-m", "mcp_nmap"],
      "cwd": "/absolute/path/to/nmap-ppro/mcp-nmap-server",
      "env": {
        "NMAP_MCP_BINARY": "/usr/local/bin/nmap",
        "NMAP_MCP_DATADIR": "/absolute/path/to/nmap-ppro"
      }
    }
  }
}
```

Omit `NMAP_MCP_BINARY` if `nmap` is already on `PATH` for that process.

**`NMAP_MCP_DATADIR`** should point at the **root of the nmap-ppro source tree**
(the directory containing `scripts/` and `nselib/`) when using `nmap_offsec_*`
tools so Nmap loads fork scripts. Omit it if your `nmap` install already ships
those scripts.

### Scanning beyond loopback

Default policy only allows **loopback** targets (`127.0.0.1`, `::1`, `localhost`, or `127.0.0.0/8`). To allow arbitrary targets:

1. Set `network_scope` to `"any"` on the tool call.
2. Set `i_acknowledge_network_scan_risk` to `true`.
3. Start the server with **`NMAP_MCP_ALLOW_ANY_TARGET=1`** in its environment.

### Offsec presets (allowlisted NSE)

`nmap_offsec_list_presets`, `nmap_offsec_dry_run`, and `nmap_offsec_run_scan` run
built-in profiles (e.g. `http_discovery`, `k8s_api_audit`, `intrusive_canaries`)
that include a fixed `--script` list. This path **does not** require
`NMAP_MCP_ALLOW_UNSAFE_CLI=1`.

- Set **`NMAP_MCP_DATADIR`** to your nmap-ppro tree when scripts live in the fork.
- Preset **`intrusive_canaries`** additionally requires **`allow_intrusive_offsec=true`**
  on the tool call **and** **`NMAP_MCP_OFFSEC_INTRUSIVE=1`** in the server environment.

Optional tuning flags may be passed as `extra_scan_options` (only `-p`, `-Pn`,
`-n`, `--open`, `-sV`/`-sT`/`-sS`, `-T0`..`-T5`, `--max-retries`).

See `docs/nse-offsec-scripts.md` in the repository for script behavior and legal
warnings.

## Tools

| Tool | Purpose |
|------|--------|
| `nmap_version` | `nmap --version` |
| `nmap_help` | `nmap --help` |
| `nmap_dry_run` | Validate argv; no execution |
| `nmap_run_scan` | Run Nmap (list argv, no shell) |
| `nmap_parse_xml_summary` | Compact struct from `-oX -` output |
| `nmap_offsec_list_presets` | List curated offsec preset ids |
| `nmap_offsec_dry_run` | Validate argv for a preset |
| `nmap_offsec_run_scan` | Run Nmap with a preset (`-oX -`) |

## Security

Nmap is a **network scanner**. This server uses `subprocess` with argument lists (no shell), blocks common injection characters in arguments, caps timeouts and argument counts, and defaults to loopback-only targets.

**Safe CLI policy (default)** for `nmap_dry_run` / `nmap_run_scan`: disallows NSE and related flags (`--script*`, `-A`, `-sC` / any `-s…` containing `C`), `-iL` / `--iL` / `--excludefile`, `-iR` / `--iR`, `--resume`, `--proxies` / `--proxy`, `--sI`, custom `--datadir` / `--servicedb` / `--versiondb` / `--stylesheet`, `--append-output`, `--` (targets must use the `targets` parameter only), and file-writing `-o*` / long `--oN` / `--oG` / … / `--siem-log` except **stdout** (`-oX -`, `-oG -`, `-oN -`, `-oS -`, `-oM -`, long `--oX -`, etc., and `--siem-log -`).

To allow the **full** Nmap option surface (operators only), set **`NMAP_MCP_ALLOW_UNSAFE_CLI=1`** on the MCP server process.

Operators remain responsible for **who** can reach this MCP server and for **compliance** with policy and law.

## Tests

```bash
cd mcp-nmap-server
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
```

On PEP 668–managed Python (e.g. Homebrew), use a venv as above instead of
installing into the system interpreter.
