# Nmap MCP server

A [Model Context Protocol](https://modelcontextprotocol.io/) (stdio) server that lets AI agents run **Nmap** safely: version/help introspection, command validation (`nmap_dry_run`), execution (`nmap_run_scan`), and a small XML summarizer (`nmap_parse_xml_summary`).

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
        "NMAP_MCP_BINARY": "/usr/local/bin/nmap"
      }
    }
  }
}
```

Omit `NMAP_MCP_BINARY` if `nmap` is already on `PATH` for that process.

### Scanning beyond loopback

Default policy only allows **loopback** targets (`127.0.0.1`, `::1`, `localhost`, or `127.0.0.0/8`). To allow arbitrary targets:

1. Set `network_scope` to `"any"` on the tool call.
2. Set `i_acknowledge_network_scan_risk` to `true`.
3. Start the server with **`NMAP_MCP_ALLOW_ANY_TARGET=1`** in its environment.

## Tools

| Tool | Purpose |
|------|--------|
| `nmap_version` | `nmap --version` |
| `nmap_help` | `nmap --help` |
| `nmap_dry_run` | Validate argv; no execution |
| `nmap_run_scan` | Run Nmap (list argv, no shell) |
| `nmap_parse_xml_summary` | Compact struct from `-oX -` output |

## Security

Nmap is a **network scanner**. This server uses `subprocess` with argument lists (no shell), blocks common injection characters in arguments, caps timeouts and argument counts, and defaults to loopback-only targets. Operators remain responsible for **who** can reach this MCP server and for **compliance** with policy and law.

## Tests

```bash
cd mcp-nmap-server
pip install -e ".[dev]"
pytest -q
```
