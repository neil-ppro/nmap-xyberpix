# SIEM NDJSON schema (nmap-ppro)

Scan telemetry from **`--siem-log`**, **`--siem-syslog`**, and **`--siem-tag`** is emitted as **newline-delimited JSON** (one object per line). The same JSON object is embedded as the MSG payload in **RFC 5424** syslog lines when `--siem-syslog` is enabled.

## Versioning

| `schema_version` | Summary |
|------------------|---------|
| **1** | Initial versioned schema: every event includes `schema_version`, `ts`, `event`, `scan_id`, `scanner_hostname`, optional `tag` (`--siem-tag`), plus event-specific fields. |

When incrementing **`schema_version`**, update this file and [CHANGELOG](../CHANGELOG), and adjust downstream parsers (Splunk, Elastic, etc.). Prefer **additive** fields within a version when possible.

## Common fields (all events)

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Currently always `1`. |
| `ts` | string | Event timestamp, **UTC**, ISO-8601 (`…Z`). Millisecond precision on Windows; microsecond on Unix in current implementation. |
| `event` | string | Event type name (see below). |
| `scan_id` | string | Identifier for this scan run (random + time-derived prefix). |
| `scanner_hostname` | string | Result of `gethostname()` (or `"unknown"`). JSON-escaped. |
| `tag` | string | Present only if `--siem-tag` was set; label for multi-site or environment. JSON-escaped. |

## Event types

### `scan_start`

| Field | Type | Description |
|-------|------|-------------|
| `nmap_version` | string | Nmap version string. |
| `platform` | string | Build platform (`NMAP_PLATFORM`). |
| `pid` | integer | Process ID of the Nmap process. |
| `args` | string or `null` | Quoted command line (escaped JSON string) or `null` if unavailable. |

### `scan_end`

| Field | Type | Description |
|-------|------|-------------|
| `hosts_scanned` | integer | Total hosts scanned. |
| `hosts_up` | integer | Hosts reported up. |
| `elapsed_sec` | number | Wall time since scan start (3 decimal places in current implementation). |

### `host`

| Field | Type | Description |
|-------|------|-------------|
| `target_ip` | string | Primary target IP string. |
| `target_hostname` | string | Resolved / known hostname (may be empty). |
| `status` | string | e.g. `up`, `down`, `timeout`, `unknown`, smurf states. |

### `port`

| Field | Type | Description |
|-------|------|-------------|
| `target_ip` | string | Host for this row. |
| `port` | integer | Port number. |
| `protocol` | string | e.g. `tcp`, `ip`. |
| `state` | string | Port state as reported by Nmap. |
| `service` | string or `null` | Service name if known. |
| `version` | string or `null` | Version string if detected. |

### `os_summary`

| Field | Type | Description |
|-------|------|-------------|
| `target_ip` | string | Host. |
| `overall_result` | string | OS detection outcome summary. |
| `os_guesses` | string | Pipe-separated OS names (may be empty). |
| `best_accuracy` | number or `null` | Best guess accuracy, or `null` if N/A. |

### `service_summary`

| Field | Type | Description |
|-------|------|-------------|
| `target_ip` | string | Host. |
| `service_hostnames` | string | CSV-style hostname hints. |
| `service_ostypes` | string | CSV-style OS type hints. |
| `service_devicetypes` | string | CSV-style device hints. |
| `service_cpes` | string | CSV-style CPE strings. |

## Integration examples

See [docs/examples/siem/README.md](examples/siem/README.md) for jq, Splunk, and Elastic/Filebeat-oriented snippets.

## Operational notes

- **Stdout** (`--siem-log -`) interleaves NDJSON with normal human-oriented Nmap output; extract lines that parse as JSON.
- **File open failure** for `--siem-log /path` logs a **warning** and disables **file** SIEM output for that run; the scan continues. Combine with `--siem-syslog` if you need guaranteed delivery to the system log.
- **User documentation**: [docs/nmap.1](nmap.1) (source for the **nmap** man page) under `--siem-log` / `--siem-syslog` / `--siem-tag`.
