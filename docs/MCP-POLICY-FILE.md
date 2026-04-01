# MCP policy file (`NMAP_MCP_POLICY_FILE`)

Optional JSON file loaded by **nmap-mcp-server** on each tool invocation that touches scan argv or targets. It **adds** constraints on top of the built-in MCP safe mode and `network_scope`. The file is read with a **256 KiB** size cap; larger files are rejected. Parsed policy is cached while the path and modification time are unchanged.

## Environment

| Variable | Purpose |
|----------|---------|
| `NMAP_MCP_POLICY_FILE` | Path to JSON policy (UTF-8). If unset or empty, no file policy is applied. |
| `NMAP_MCP_AUDIT_LOG` | Append NDJSON lines for `nmap_dry_run`, `nmap_run_scan`, and offsec variants (proposed argv + completion). |

Invalid JSON or a non-object root causes tool calls to fail with an error mentioning `NMAP_MCP_POLICY_FILE`.

## JSON schema (informal)

| Field | Type | Effect |
|-------|------|--------|
| `disallowed_scan_option_prefixes` | string[] | Reject any `scan_options` token equal to or starting with one of these strings (applies even when `NMAP_MCP_ALLOW_UNSAFE_CLI=1`). |
| `disallowed_scan_options_exact` | string[] | Reject exact token matches. |
| `allowed_target_cidrs` | string[] | If non-empty, every target must be a literal IP (no hostnames) contained in one of these CIDRs (e.g. `10.0.0.0/8`). |
| `allowed_hostnames` | string[] | If `allowed_target_cidrs` is empty but this is non-empty, targets must match one of these hostnames after **case-insensitive** comparison and ignoring a trailing dot (DNS rules). If both lists are empty/absent, no extra target restriction from the file. |
| `max_targets` | integer | Maximum number of targets per call (≥ 1). |
| `max_timeout_seconds` | integer | Cap `timeout_seconds` for `nmap_run_scan` / `nmap_offsec_run_scan`. |

## Example (lab-only CIDR + script block)

```json
{
  "allowed_target_cidrs": ["127.0.0.0/8", "10.50.0.0/16"],
  "max_targets": 8,
  "max_timeout_seconds": 300,
  "disallowed_scan_option_prefixes": ["--script", "--script="]
}
```

## Audit log events

Typical `event` values:

- `mcp_nmap_dry_run` — validated argv for `nmap_dry_run`.
- `mcp_nmap_run_scan` — execution phase with trimmed `argv`.
- `mcp_nmap_run_scan_finished` — `returncode` and success flag.
- `mcp_nmap_offsec_dry_run`, `mcp_nmap_offsec_run_scan`, `mcp_nmap_offsec_run_scan_finished` — same for offsec presets.

Lines are newline-delimited JSON with a UTC `ts` field. Very long string fields (e.g. errors) and long lists are **truncated** before write so a single log line cannot exceed **256 KiB** (defense against log/memory abuse).

**Offsec tools** (`nmap_offsec_dry_run`, `nmap_offsec_run_scan`) append `phase: "scope"` audit lines when `network_scope` checks fail, matching the main `nmap_run_scan` path.
