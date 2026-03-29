# nmap-xyberpix security overview

This document ties together **safe-by-default** behavior for fork-specific features: the **MCP server**, **SIEM logging**, and **offensive-research NSE**. It does not replace upstream Nmap’s own security model (privileges, network access, script safety levels).

## Threat model (MCP)

When an AI agent or automation uses `mcp-nmap-server`:

1. **Argv injection** — Nmap continues to parse tokens that look like options after real targets (`getopt_long_only`). A “target” string starting with `-` or a Unicode dash can be treated as a flag. The MCP server rejects such targets and forbids `--` in `scan_options` so targets only come from the dedicated parameter.
2. **Policy bypass** — Safe mode blocks NSE (`--script`, `-A`, `-sC` forms), arbitrary file reads (`-iL`, `--iL`, …), most non-stdout outputs (`-oN file`, long `--oG` paths, …), resume/proxies/`--ssh-bounce`/idle scan flags, and several long options that change data paths. See the detailed write-ups below for historical bypass classes.
3. **Network scope** — By default only **loopback** targets are allowed unless the tool explicitly requests `network_scope=any`, sets `i_acknowledge_network_scan_risk=true`, and the server process has **`NMAP_MCP_ALLOW_ANY_TARGET=1`**.

Operators who need the full Nmap CLI from MCP must set **`NMAP_MCP_ALLOW_UNSAFE_CLI=1`** (trusted environments only).

## MCP environment variables (quick reference)

| Variable | Effect |
|----------|--------|
| `NMAP_MCP_BINARY` | Path to `nmap` if not on `PATH` (must be a real executable file; no shell metacharacters). |
| `NMAP_MCP_ALLOW_ANY_TARGET` | Must be `1` for non-loopback targets when the tool uses `network_scope=any`. |
| `NMAP_MCP_ALLOW_UNSAFE_CLI` | Must be `1` to allow NSE, `-iL`, file outputs, `--datadir`, etc. |
| `NMAP_MCP_DATADIR` | Repository root (contains `scripts/`, `nselib/`) for fork scripts without unsafe CLI; used by offsec presets. |
| `NMAP_MCP_OFFSEC_INTRUSIVE` | Must be `1` for intrusive offsec preset plus tool flag `allow_intrusive_offsec`. |

Curated **offsec presets** (`nmap_offsec_*`) use a fixed allowlisted `--script` set and do **not** require `NMAP_MCP_ALLOW_UNSAFE_CLI` when `NMAP_MCP_DATADIR` points at this tree.

## Deeper reading

| Topic | Document |
|--------|-----------|
| MCP tools, defaults, offsec presets | [mcp-nmap-server/README.md](../../mcp-nmap-server/README.md) |
| Target / argv injection | [MCP-TARGET-ARGV-INJECTION.md](MCP-TARGET-ARGV-INJECTION.md) |
| Scan-options policy bypass notes | [MCP-SCAN-OPTIONS-POLICY-BYPASS.md](MCP-SCAN-OPTIONS-POLICY-BYPASS.md) |
| Offsec NSE scripts, legal use, script-args | [../nse-offsec-scripts.md](../nse-offsec-scripts.md) |
| SIEM JSON fields and versioning | [../SIEM-NDJSON-SCHEMA.md](../SIEM-NDJSON-SCHEMA.md) |
| SIEM pipeline examples (jq, Splunk, Elastic) | [../examples/siem/README.md](../examples/siem/README.md) |

## Zenmap XML (SAX)

Zenmap parses Nmap XML with **`xml.sax`** (same family as Python’s `xml.etree`). Parsers used for scan results, RadialNet, and `--script-help` XML are configured to **disable external general/parameter entities** and use an **empty entity resolver** so DTD resolution does not fetch remote resources. **`<output type="interactive">`** text is **capped** (32 MiB of character data) to limit memory when opening a hostile XML file; RadialNet caps text per element (4 MiB). Treat scan XML like untrusted input when it did not come from your own Nmap run.

## SIEM logging

`--siem-log` writes **NDJSON** (one JSON object per line). Do not confuse with interactive Nmap stdout; ship lines that parse as JSON to your log pipeline. Failed SIEM **file** open emits a warning and the scan continues (syslog mirroring still works if enabled). The **`scan_start`** `args` field is a **UTF-8 prefix** of the quoted command line (currently **128 KiB** max) before JSON escaping, so pathological argv does not grow unbounded log lines. See [SIEM-NDJSON-SCHEMA.md](../SIEM-NDJSON-SCHEMA.md).

## nfuzz (raw IPv4 / stream / Bluetooth L2CAP fuzzer + HTTP browser fuzz server)

The optional **`nfuzz`** binary (built with Nmap on Unix unless `./configure --without-nfuzz`) can send **mutated IPv4 datagrams** via a raw socket, send **mutated TCP or UDP application payloads** to **`--dst`/`--dport`** (**`--proto`**), or send **mutated L2CAP payloads** (**`--bt-l2cap`**) using **IOBluetooth on macOS** or **BlueZ on Linux** when the corresponding build is enabled. It can also run **`--http-daemon`**, a small HTTP server that returns a **fresh fuzzed HTML/JS page** on every request (for authorized DOM/JS engine testing in a lab). With **`--auto-browser`**, it can **spawn and supervise** a headless browser process pointed at that URL (optional periodic restart). **`--browser-cmd`**, **`NFUZZ_BROWSER_CMD`**, **`--browser-url`**, and each **`--browser-arg`** must be a single **`execvp`** token or URL string with **no ASCII control bytes (including DEL)** and no **`;|&` `$` or backtick** in command tokens (defense in depth; there is no shell). HTTP requests are read with a **fixed buffer**; **header detection scans raw bytes** so an embedded **NUL** cannot hide the end-of-headers delimiter. **`--hex-file`** must be a **regular file** and is opened with **`O_NOFOLLOW`** where the OS supports it; **`--pid-file`** is written **without following symlinks** where supported. Responses do not interpret the request path (always the same fuzz page). By default the daemon binds to **loopback** only; **`--http-allow-remote`** is required to listen on other interfaces. It is **not** part of MCP and is not installed on MinGW/Cygwin builds. It refuses to run unless **`--authorized`** or **`NFUZZ_AUTHORIZED=1`** is set. Raw mode typically needs **superuser**; HTTP and stream (TCP/UDP) modes do not. Bluetooth use depends on **local capability policy** and **macOS privacy prompts** where applicable. Misuse can violate law or contract and can disrupt networks, radios, or crash browsers. See **`nfuzz(1)`**.

## ngit (GitHub repository secret scanner)

The optional **`ngit`** script (installed with Nmap on Unix when Python 3 is available unless `./configure --without-ngit`) clones GitHub repositories with **`git`** and scans working-tree text files for **many credential patterns** (cloud keys, tokens, DB URLs, PEM private keys, optional PEM public certs via **`--include-certificates`**, webhooks, plus **`--extra-regex LABEL=PATTERN`** for custom rules). Finding **types** can be filtered with **`--type`** / **`--exclude-type`** (shell-style globs). **`--keyword`** and **`--keyword-file`** narrow regex hits to lines containing those strings, or **`--keyword-scan`** can search for keywords alone. It **streams each finding immediately** to stdout (repository, path:line, type, value); **values are redacted by default**—**`--show-secrets`** prints full matches (unsafe for logs or shared terminals). It supports **`--repo OWNER/NAME`**, **`--scan-count N`** with the GitHub **`search/repositories`** API, and **`--random`**. It **refuses to run** without **`--authorized`** or **`NGIT_AUTHORIZED=1`**. Operators must use it **only on repositories they own or are explicitly authorized to assess**; bulk scanning of arbitrary public repositories can violate **law**, **contract**, and **GitHub’s terms of use**. **`GITHUB_TOKEN`** / **`GH_TOKEN`** (or **`--token`**) is recommended for API rate limits and for private repositories the token may read. The implementation **validates `OWNER/NAME` slugs**, **caps GitHub API response size**, **rejects token control characters** (header injection), **skips symlinked regular files** in the clone, **sanitizes finding header lines** (log injection), bounds **`--search-query`** / keywords / **`--extra-regex`** size, and ignores **`..`** relative path segments; untrusted **`--extra-regex`** patterns can still be **CPU-heavy** (**regular-expression denial of service**)—use only trusted patterns. Output is heuristic and will **false positive**; it is not a substitute for dedicated secret scanners in CI. Not installed on MinGW/Cygwin builds. See **`ngit(1)`**.

## Xyberpix GUI

The **xyberpix-gui** helper runs **Nmap**, **Nping**, **Ncat**, and **nfuzz** via **`QProcess`** with an explicit argv list (**no shell**). User-typed “extra” flags and multi-target lines are split with POSIX **`shlex`** rules through **`xyberpix_gui.argv_utils`**, which rejects **NUL** bytes, caps **UTF-8 size** and **token count**, and reports **quoting errors** before starting the child. **`ProcessRunner`** re-checks arguments and shows a **`shlex.join`**-style status preview. Per-tool binary overrides and **`NMAP_XYBERPIX_ROOT`** ignore paths containing **NUL**.

## NSE (offsec scripts)

Use only on **authorized** targets. Intrusive scripts require explicit **`SCRIPT_NAME.unsafe=1`** (or equivalent) via `http_offsec.intrusive_gate` where applicable. Adding a new script to **MCP** presets requires updating the allowlist in `mcp_nmap/server.py` and running **`maint/check_offsec_mcp_sync.py`** (see [nse-offsec-scripts.md](../nse-offsec-scripts.md)).

## Automated checks in CI

The workflow **nmap-xyberpix-checks** runs MCP unit tests on **Ubuntu and Windows**, Zenmap flag consistency, offsec/MCP sync, a **`nmap.cc` long-options baseline** check (forces review of MCP safe mode when new `--long-opts` appear), and a **SIEM smoke** job that reuses the built `nmap` binary from an artifact. See [.github/workflows/nmap-xyberpix-checks.yml](../../.github/workflows/nmap-xyberpix-checks.yml).
