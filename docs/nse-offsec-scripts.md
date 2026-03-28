# nmap-xyberpix offensive-research NSE scripts

This document describes **optional** scripts in the nmap-xyberpix fork that support
authorized security assessments (API mapping, JWT header review, GraphQL
introspection checks, Kubernetes API posture, and higher-risk canary probes).

## Legal and policy

Use these scripts **only** on systems and networks you are **explicitly
authorized** to test. Unauthorized scanning may violate law and contract.
Operators are responsible for scope, consent, logging, and data handling.

## Shared library: `nselib/http_offsec.lua`

Several scripts use `http_offsec` for:

- Default path lists (OpenAPI/Swagger, GraphQL HTTP endpoints).
- SSRF-style canary URL sets and cloud metadata probe targets.
- **`intrusive_gate(script_name)`** — intrusive scripts refuse to run until
  **`SCRIPT_NAME.unsafe=1`** (or `true`) is set in `--script-args`, after you
  accept the risk of outbound fetches, noisy errors, or SSRF-like behavior.
- **`assert_safe_http_request_path` / `assert_safe_basepath`** — reject paths
  with NUL/CR/LF/whitespace, enforce a leading `/`, and cap length so HTTP
  request lines cannot be split or abused via `--script-args` paths.

## MCP server note

If you use **`mcp-nmap-server`**, start with
[`docs/security/SECURITY-OVERVIEW.md`](security/SECURITY-OVERVIEW.md), then
[`docs/security/MCP-TARGET-ARGV-INJECTION.md`](security/MCP-TARGET-ARGV-INJECTION.md)
for how target parameters are validated (Nmap option injection).

## Script index (authorized use only)

Every script below is **optional** and must be run only with **written authorization** for the target. **Intrusive** rows perform outbound requests that may be noisy or sensitive; they are gated by **`SCRIPT_NAME.unsafe=1`** (and MCP uses additional env/tool flags for presets).

### Reference table

| Script | Intrusive | Required / notable `--script-args` | `http_offsec` helpers | In MCP allowlist |
|--------|-----------|------------------------------------|-----------------------|------------------|
| `http-openapi-map` | no | none | path safety for probe URLs | yes (`http_discovery` preset) |
| `http-graphql-introspect` | no | none | path safety | yes (`http_discovery`) |
| `http-jwt-probe` | no | **`http-jwt-probe.jwt=`** JWT for prerule decode | path safety | yes (`http_discovery`; dummy JWT in preset) |
| `k8s-api-anon-audit` | no | none | path safety | yes (`k8s_api_audit`) |
| `http-ssrf-canary` | yes | **`http-ssrf-canary.unsafe=1`**, **`http-ssrf-canary.template=`** (must contain `CANARY`) | `intrusive_gate`, path safety | yes (`intrusive_canaries`) |
| `http-cloud-metadata-reach` | yes | **`http-cloud-metadata-reach.unsafe=1`** | `intrusive_gate`, path safety | yes (`intrusive_canaries`) |
| `http-llm-proxy-leak` | yes | **`http-llm-proxy-leak.unsafe=1`** | `intrusive_gate`, path safety | yes (`intrusive_canaries`) |
| `http-oauth-misconfig` | no | optional **`http-oauth-misconfig.basepath=`** (must pass `http_offsec` checks) | `assert_safe_basepath`, `assert_safe_http_request_path` on full path | **no** — use full Nmap CLI or `NMAP_MCP_ALLOW_UNSAFE_CLI` |
| `http-websocket-hunt` | no | optional **`http-websocket-hunt.basepath=`** (same checks) | `assert_safe_basepath`, `assert_safe_http_request_path` | **no** |
| `tls-clientcert-optional-downgrade` | no | optional **`tls-clientcert-optional-downgrade.basepath=`** (prefix for probe paths) | `assert_safe_basepath`, `assert_safe_http_request_path` | **no** |
| `proto-generic-fuzzer` | yes | **`proto-generic-fuzzer.unsafe=1`**, **`payload_hex=`** and/or **`random_len=`**; optional **`strategies=`**, **`iterations=`** (≤500), **`chain_depth=`**, **`transport=`** (`tcp`/`udp`/`ssl`), **`reuse=`**, **`delay_ms=`**, **`recv=`**, **`recv_bytes=`**, **`seed=`** | — (non-HTTP; use `intrusive_gate` only) | **no** — use full Nmap CLI |

For **layer-3** IPv4 mutation at high send rates, use the optional **`nfuzz`**
binary (see **`nfuzz(1)`** and [SECURITY-OVERVIEW.md](security/SECURITY-OVERVIEW.md)); the **`proto-generic-fuzzer`** script operates at **connected TCP/UDP/SSL**.

**MCP allowlist** scripts are enforced in `mcp_nmap/server.py` (`_OFFSEC_ALLOWED_SCRIPTS` and preset `options`). Other scripts in this table ship with the fork but are **not** exposed through `nmap_offsec_*` tools unless you extend the allowlist and run **`python3 maint/check_offsec_mcp_sync.py`** (and CI).

### Maintainer checklist (new or changed scripts)

1. If the script uses HTTP with user-influenced paths, prefer **`http_offsec.assert_safe_http_request_path`** / **`assert_safe_basepath`** (see `nselib/http_offsec.lua`).
2. If the script is intrusive, use **`http_offsec.intrusive_gate`** and document **`SCRIPT_NAME.unsafe=1`** in this file (including non-HTTP scripts such as **`proto-generic-fuzzer`**).
3. If the script should appear in **MCP offsec presets**, add the basename to **`_OFFSEC_ALLOWED_SCRIPTS`**, extend **`_OFFSEC_PRESETS`**, and run **`maint/check_offsec_mcp_sync.py`** so `scripts/*.nse` and this doc stay aligned.
4. Add a row to the table above with **Intrusive**, **script-args**, and **MCP allowlist** columns.

### Example: safe HTTP discovery (localhost)

```bash
nmap -p 8080 --script http-openapi-map,http-graphql-introspect \
  --script-args 'http-jwt-probe.jwt=eyJhbGciOiJIUzI1NiJ9.e30.z' \
  127.0.0.1
```

### Example: intrusive SSRF-style canary (authorized target only)

```bash
nmap -p 80,443 --script http-ssrf-canary \
  --script-args 'http-ssrf-canary.template=/fetch?url=CANARY,http-ssrf-canary.unsafe=1' \
  target.example
```

### Example: Kubernetes API-style ports

```bash
nmap -p 6443,8443,8001 --script k8s-api-anon-audit target.example
```

Use normal Nmap SSL options (e.g. `--script ssl-cert`) when the API uses
self-signed certificates and HTTP requests fail.

## MCP integration (`mcp-nmap-server`)

The MCP server exposes **`nmap_offsec_list_presets`**, **`nmap_offsec_dry_run`**,
and **`nmap_offsec_run_scan`** so agents can run a **fixed, allowlisted**
`--script` set **without** enabling the full unsafe CLI (`NMAP_MCP_ALLOW_UNSAFE_CLI`).

- Set **`NMAP_MCP_DATADIR`** to the **root of the nmap-xyberpix tree** (the
  directory containing `scripts/` and `nselib/`) so Nmap loads fork scripts.
- Intrusive preset **`intrusive_canaries`** requires **`allow_intrusive_offsec=true`**
  on the tool call **and** **`NMAP_MCP_OFFSEC_INTRUSIVE=1`** in the server
  environment.

See `mcp-nmap-server/README.md` for general MCP security policy.

## Automated checks

- **`maint/check_offsec_mcp_sync.py`** — MCP allowlist ↔ `scripts/*.nse` ↔ this document (run after editing presets or the table).
- **`maint/nse_offsec_selftest.py`** — starts a tiny local HTTP server on a **likely HTTP port** (see `shortport.http` / `LIKELY_HTTP_PORTS` so `portrule` matches) and runs a few Nmap invocations against `127.0.0.1`. Set **`NMAP_SELFTEST_BINARY`** if `nmap` is not on `PATH`. The script passes `--datadir` to the repository root so fork `scripts/` and `nselib/` load. The intrusive-gate check runs Nmap with **`-d`**: `stdnse.format_output(false, ...)` normally omits failure text from script output unless debugging is enabled.

CI runs the sync script and MCP tests under **nmap-xyberpix checks** (see `.github/workflows/nmap-xyberpix-checks.yml`).
