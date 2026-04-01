# Security-oriented static review: Nmap / Ncat / Nping / nfuzz (C) and NSE

**Date:** 2026-03-27 (nmap-xyberpix)  
**Type:** Automated static pattern scan + targeted manual review of fork helpers — **not** a substitute for a full commercial penetration test, formal verification, or continuous fuzzing of the entire codebase.

## Executive summary

- **Scope claim:** A literal “full” manual audit of every line in **Nmap’s C/C++ core**, **Ncat**, **Nping**, **nfuzz**, and **all 623 `scripts/*.nse` files** would require a dedicated team and weeks to months. This document records what **was** done: **repeatable `rg`/`grep` passes**, architecture review, and **spot checks** on fork-specific NSE helpers (`nselib/http_offsec.lua`).
- **Bottom line:** The tree contains **intentionally powerful** components (network scanner, **Ncat `--exec` / shell**, **NSE** probing and exploits). Security posture depends on **operator authorization**, **least privilege**, **script categories**, and **sandbox options** — not on “safe by default” for every script.
- **Automation:** Run `maint/security_audit_static_grep.sh` from the repo root to reproduce the high-signal greps below.

## In-scope components

| Area | Approx. scale | Notes |
|------|----------------|-------|
| `nmap` + `nbase` + `nsock` + `libnetutil` + related | Very large | Core scanner, parsing, output, privileges |
| `ncat/` | Large | Proxies, TLS, **`/bin/sh -c`** when `EXEC_SHELL` |
| `nping/` | Large | Raw / privileged probes on some platforms |
| `nfuzz/` | Medium | Raw sockets, HTTP daemon, **`execvp`** browser launch |
| `scripts/*.nse` | **623** files | Many are **intrusive** / **vuln** / **brute** by design |
| `nselib/*.lua` | Large | Libraries used by scripts |
| Bundled deps (`liblua/`, `libpcap/`, `libssh2/`, …) | Very large | **Out of scope** for line review; track **upstream CVEs** |

## Methodology (what “audit” means here)

1. **Static pattern search** over fork-owned and core trees via `maint/security_audit_static_grep.sh` (uses `grep -R` with `--exclude-dir` for bundled libs). The script **does not** grep for `system(` because natural-language comments (“… the system (TCP …”) flood the output; search `system` call sites with a manual query or SAST when needed.
2. **Architecture / trust-boundary** notes (subprocess, shell, NSE capabilities).
3. **Fork-specific library review:** `http_offsec.lua` (path gates, intrusive gating).
4. **No:** exhaustive manual review of every C function, every script, every third-party file.

## High-risk patterns — results summary

### Process creation / shell (`exec*`, `system`, `popen`, `CreateProcess`)

Representative hits (non-exhaustive):

| Location | Behavior | Risk context |
|----------|----------|--------------|
| `ncat/ncat_posix.c` | `execl("/bin/sh", "sh", "-c", cmdexec, …)` when `EXEC_SHELL` | **Expected:** user explicitly requests shell execution (`-c` / `--exec`). Command injection if **untrusted** input reaches `cmdexec`. |
| `ncat/ncat_posix.c` | `execv(cmdargs[0], cmdargs)` after `cmdline_split` | No shell; argv split semantics matter. |
| `nfuzz/nfuzz.c` | `execvp(cmd, argv)` for browser | **Expected:** lab feature; `cmd` and args are validated elsewhere in nfuzz (see `nfuzz(1)` / SECURITY-OVERVIEW). |
| `ssh_bounce.cc` | `execvp("ssh", argv)` | **Expected:** bounce helper builds fixed `ssh` argv. |
| `siem_log.cc` | `popen("logger -t nmap-siem", "w")` etc. | **Constant command**; only **stdin** pipe used for log data — **not** user-controlled shell string. |
| Bundled `liblua` | `system` / `popen` in library | Lua VM surface; Nmap **restricts** many libs in the NSE sandbox (see upstream docs). |

### Unsafe C string APIs (`strcpy`, `strcat`, `sprintf`, `gets`)

- **Many hits** are to **fixed string literals** or **buffers sized for known constants** (e.g. ICMP type names in `libnetutil/netutil.cc`, paths like `/etc/services` in `services.cc`).
- **Residual risk:** any `strcpy` into a **user-influenced** or **variable-length** buffer without a proven bound remains a **candidate for snprintf/strlcpy-style hardening**. A full audit would **triage each call site** (Coverity, CodeQL, or manual).

### Temporary files

- `ncat/ncat_connect.c`: **Unix datagram** path uses **`mkstemp`** when `HAVE_MKSTEMP` is defined (**preferred**).
- **Fallback** `#else` uses **`tempnam(3)`**, which is **deprecated / race-prone** on ancient platforms without `mkstemp`. **Recommendation:** build with **`mkstemp`** available; treat non-`mkstemp` builds as **legacy**.

### NSE: `loadfile`

Hits include scripts such as `http-enum.nse`, `http-default-accounts.nse`, `smb-psexec.nse`, `tftp-version.nse`, etc. These load **user-supplied or configured** Lua data files with **`loadfile(..., "t", env)`** (Lua 5.4+ **text mode** — no native bytecode).

**Risk:** Loading **malicious Lua** from a **malicious path** is dangerous. Mitigations are **operational** (trusted data dirs, permissions) and **Lua sandbox** policy — not “safe” arbitrary paths.

### NSE: `os.execute` / `io.popen` in `scripts/`

- **No matches** in `scripts/*.nse` in the scan run (Nmap’s default exposure of `os` is limited; verify with your Lua/Nmap version).
- **`nselib`:** scan any uses directly; upstream may use restricted APIs in practice.

## Fork-specific review: `nselib/http_offsec.lua`

Reviewed for **HTTP request splitting** and **path injection**:

- **`assert_safe_http_request_path`:** requires leading `/`, max length **8192**, rejects **NUL/CR/LF/whitespace** (reduces **header splitting** / **absolute-form** abuse in request line construction).
- **`assert_safe_basepath`:** same style checks for optional base prefix.
- **`intrusive_gate`:** requires **`SCRIPT_NAME.unsafe=1`** (or `true`) for intrusive fork scripts.

This is **defense in depth**; it does **not** remove legal/authorization obligations.

## Threat model (condensed)

| Actor | Concern |
|-------|---------|
| **Operator running Nmap as root / with `--privileged`** | Full host compromise via bugs in scanner or scripts. |
| **Operator running Ncat `--exec` / `--sh-exec`** | Shell/command execution as the Ncat user. |
| **Attacker feeding scan input** (e.g. malicious service banners, crafted responses) | Parser bugs, memory corruption, NSE logic errors. |
| **Attacker controlling script args / data files** | `loadfile`, path tricks, brute payloads — **authorized testing only**. |

## Recommendations (ongoing, not one-shot)

1. **Upstream tracking:** Subscribe to **Nmap / Npcap / OpenSSL / Lua** security advisories.
2. **Build hygiene:** ASAN/UBSAN CI where feasible; **`-D_FORTIFY_SOURCE`**, **stack canaries**, **relro**, **PIE** (platform-dependent).
3. **Fuzzing:** Nmap has history of fuzzing **parsing** paths; extend to **your fork diffs** (`siem_log`, `nfuzz`, `ssh_bounce`, etc.).
4. **NSE:** Run only **needed** scripts; use **`--script` allowlists**; understand **`safe` vs `intrusive`** categories.
5. **Re-run** `maint/security_audit_static_grep.sh` after large merges; diff against prior output.

## Limitations of this document

- Does **not** certify the absence of vulnerabilities.
- Does **not** review **Zenmap**, **Python MCP**, **xyberpix-gui**, or **nxytools** (covered elsewhere).
- **Third-party** trees under `liblua/`, `libpcap/`, `libssh2/`, etc. are **not** manually audited here.

## Related documentation

- [SECURITY-OVERVIEW.md](SECURITY-OVERVIEW.md)
- [OPERATORS.md](OPERATORS.md)
- [nse-offsec-scripts.md](../nse-offsec-scripts.md)
- [MCP-TARGET-ARGV-INJECTION.md](MCP-TARGET-ARGV-INJECTION.md)
