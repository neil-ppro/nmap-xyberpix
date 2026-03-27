# MCP server: target parameter argv injection (fixed)

## Summary

**Component:** `mcp-nmap-server` (`mcp_nmap/server.py`)

**Severity:** High for deployments that treat the MCP server as a *policy boundary*
(e.g. agents limited to `loopback_only` and “safe” `scan_options`, with
`NMAP_MCP_ALLOW_UNSAFE_CLI` unset).

**CVE:** Not assigned (fork-specific integration).

## Root cause

Nmap parses the command line with `getopt_long_only()` and continues to treat
tokens that look like options as options even **after** normal target hostnames
(`nmap.cc`). The MCP tools build:

```text
argv = [nmap_binary] + scan_options + targets
```

So values passed in the `targets` list are **not** guaranteed to be “targets
only”. Any string starting with `-` (or certain Unicode dash characters that
Nmap rejects) can be interpreted as Nmap flags.

That allowed **policy bypass**: `scan_options` could stay “safe” while
`targets` appended flags such as `-oN`, `--script`, `--datadir`, etc.

## Proof of concept (before fix)

With `NMAP_MCP_ALLOW_UNSAFE_CLI` unset and `network_scope="loopback_only"`, a
malicious client could still obtain an argv such as:

```text
nmap -sn 127.0.0.1 -oN /tmp/mcp-pwned.xml
```

by calling `nmap_dry_run` / `nmap_run_scan` with:

```python
targets = ["127.0.0.1", "-oN", "/tmp/mcp-pwned.xml"]
```

The same pattern works for other flags that were meant to be blocked in the
`scan_options` list only.

A runnable PoC script lives at:

`docs/security/poc_mcp_target_argv_injection_demonstration.py`

## Remediation (applied)

1. **`_validate_target_entry`** — Rejects targets that start with `-`, ASCII or
   common Unicode dashes (aligned with Nmap’s own “dash, not hyphen” check),
   and rejects `--`.
2. **`\0` in `_FORBIDDEN_ARG_CHARS`** — Blocks NUL in any argv fragment passed
   through validation.

## Non-issues in the same area

- **Subprocess list invocation** — No shell; mitigates shell metacharacter
  injection. Option injection is separate and addressed above.

## Related: scan_options policy gaps (long `-o*`, `--iL`, `-iR`, …)

Even with safe `targets`, **`scan_options`** could bypass the original policy
via Nmap’s long-option forms. See
[`MCP-SCAN-OPTIONS-POLICY-BYPASS.md`](MCP-SCAN-OPTIONS-POLICY-BYPASS.md).

---

# NSE HTTP scripts: request-line injection via path / template (fixed)

## Summary

**Component:** `nselib/http_offsec.lua`, intrusive/safe HTTP scripts using
`http.get` / `http.post`.

**Severity:** Medium (abuse requires `--script-args` from someone who can already
run NSE against the host; impact is malformed HTTP toward the scanned service,
possible cache/proxy oddities, not a direct RCE in Nmap).

## Root cause

`nselib/http.lua` builds:

```text
request_line = method .. " " .. path .. " HTTP/1.1"
```

User-controlled `path` / `template` values containing CR/LF, NUL, whitespace, or
not starting with `/` could break the request line or behave like absolute-form
targets.

## Remediation (applied)

`http_offsec.assert_safe_http_request_path` and `assert_safe_basepath` enforce:

- Leading `/`, no NUL/CR/LF, no whitespace, length cap.
- Scripts validate basepath and every final path (including after CANARY
  substitution).

See `docs/nse-offsec-scripts.md` for script-level usage.
