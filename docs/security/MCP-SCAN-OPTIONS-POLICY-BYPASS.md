# MCP server: scan_options policy bypasses (fixed)

## Summary

**Component:** `mcp-nmap-server` — `_scan_options_policy_error()` in `mcp_nmap/server.py`

**Severity:** High for deployments relying on default “safe” MCP mode (no
`NMAP_MCP_ALLOW_UNSAFE_CLI`) to cap **file I/O**, **target selection**, and
**proxying**.

## Issues found and fixed

### 1. Long-form output flags (`--oN`, `--oG`, `--oX`, …)

Safe mode only validated **short** `-oN`, `-oG`, `-oX`, etc. Nmap also accepts
**long** `--oN`, `--oG`, `--oX` (see `nmap.cc` `long_options`). Those long forms
skipped the short-option branch entirely, so callers could pass
`--oN /path/to/file` and **write scan output to an arbitrary path** on the MCP
host while still appearing to use “safe” scan lines.

**Fix:** `_policy_long_o_output_error()` applies the same rules as short `-o*`
(only `-` / stdout for `NGXSM`, block `AH`).

### 2. Long-form host list (`--iL`)

`-iL` was blocked, but **`--iL`** (same option, long form) was not, enabling
**arbitrary file read** for host list input.

**Fix:** Reject `--iL` and `--iL=` the same as `-iL`.

### 3. Random targets (`-iR` / `--iR`)

**`-iR`** makes Nmap generate random targets (`nmap.cc`), which **circumvents**
MCP’s intent when combined with `network_scope=loopback_only` and explicit
targets (Nmap can still scan non-loopback addresses).

**Fix:** Reject `-iR` and any argument starting with `-iR`, and reject `--iR` /
`--iR=`.

### 4. Resume and proxy / idle-scan knobs

- **`--resume`** — reads prior scan state from a path (file read / surprising
  behavior in an MCP-driven flow).
- **`--proxies` / `--proxy`** — redirects scan traffic via an attacker-chosen
  proxy.
- **`--ssh-bounce` / `--ssh-bounce-port`** — (nmap-ppro) spawns `ssh -D` or
  selects a jump host port; same policy class as proxies.
- **`--sI`** — idle scan (zombie) configuration.

**Fix:** Reject these in safe mode unless `NMAP_MCP_ALLOW_UNSAFE_CLI=1`.

## Proof of concept (behavior after fix)

The following are **rejected** by `nmap_dry_run` in default safe mode:

```text
--oN /tmp/pwned.xml
--iL /etc/passwd
-iR 100
--resume previous.xml
--proxies http://attacker:8080
--ssh-bounce user@attacker.example
```

A small checker script:

`docs/security/poc_mcp_scan_options_policy_bypass_demonstration.py`

(Run with the same Python environment as `mcp-nmap-server`; see script
docstring.)

## Relationship to other advisories

See also
[`MCP-TARGET-ARGV-INJECTION.md`](MCP-TARGET-ARGV-INJECTION.md) for **target**
parameter injection into Nmap’s argv.
