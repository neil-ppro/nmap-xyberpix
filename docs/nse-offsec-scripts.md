# nmap-ppro offensive-research NSE scripts

This document describes **optional** scripts in the nmap-ppro fork that support
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

If you use **`mcp-nmap-server`**, see
[`docs/security/MCP-TARGET-ARGV-INJECTION.md`](security/MCP-TARGET-ARGV-INJECTION.md)
for how target parameters are validated (Nmap option injection).

## Script reference

| Script | Category | Notes |
|--------|----------|--------|
| `http-openapi-map` | discovery | GETs common OpenAPI/Swagger paths; parses JSON when possible; flags path names matching sensitive keywords. |
| `http-graphql-introspect` | discovery | POSTs an introspection query to common GraphQL paths. |
| `http-jwt-probe` | discovery | **Prerule:** decodes a JWT header from `http-jwt-probe.jwt`; flags `alg=none`, `jku`/`x5u`, odd `kid`. Does not fetch JWKS. |
| `k8s-api-anon-audit` | discovery | GETs `/version`, `/api`, `/api/v1/namespaces`; classifies anonymous JSON vs 401/403 vs failures. |
| `http-ssrf-canary` | intrusive | Requires **`http-ssrf-canary.unsafe=1`** and `http-ssrf-canary.template` containing literal `CANARY`. |
| `http-cloud-metadata-reach` | intrusive | Requires **`http-cloud-metadata-reach.unsafe=1`**; probes metadata-style URLs from the scanner (not SSRF through an app). |
| `http-llm-proxy-leak` | intrusive | Requires **`http-llm-proxy-leak.unsafe=1`**; probes LLM-style paths with a dummy `Authorization` header. |

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

- Set **`NMAP_MCP_DATADIR`** to the **root of the nmap-ppro tree** (the
  directory containing `scripts/` and `nselib/`) so Nmap loads fork scripts.
- Intrusive preset **`intrusive_canaries`** requires **`allow_intrusive_offsec=true`**
  on the tool call **and** **`NMAP_MCP_OFFSEC_INTRUSIVE=1`** in the server
  environment.

See `mcp-nmap-server/README.md` for general MCP security policy.

## Automated check

`maint/nse_offsec_selftest.py` starts a tiny local HTTP server on a **likely
HTTP port** (see `shortport.http` / `LIKELY_HTTP_PORTS` so `portrule` matches)
and runs a few Nmap invocations against `127.0.0.1`. Set
**`NMAP_SELFTEST_BINARY`** if `nmap` is not on `PATH`. The script passes
`--datadir` to the repository root so fork `scripts/` and `nselib/` load.

The intrusive-gate check runs Nmap with **`-d`**: `stdnse.format_output(false,
...)` normally omits failure text from script output unless debugging is
enabled.
