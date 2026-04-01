# Fork-only C/C++ core: security inventory vs upstream Nmap

**Purpose:** Operational checklist for **nmap-xyberpix** C/C++ that is fork-owned or high-churn vs [Nmap](https://github.com/nmap/nmap): what to re-review on every upstream merge and how to generate a real `git diff`.

**Not a substitute for:** full manual audit of unchanged upstream code or SAST on the whole tree.

## 1. Diff against upstream

Per [UPSTREAM-MERGE.md](../UPSTREAM-MERGE.md):

```bash
git remote add upstream https://github.com/nmap/nmap.git   # once
git fetch upstream master
./maint/fork_c_upstream_diff.sh
```

Or:

```bash
git diff upstream/master...HEAD --stat -- '*.c' '*.cc' '*.h'
git diff upstream/master...HEAD --name-only -- '*.c' '*.cc' '*.h'
```

Adjust `master` if upstream uses another default branch. If you cannot fetch, use **section 2** as the review list.

Override the left-hand ref if needed:

```bash
UPSTREAM_REF=upstream/main ./maint/fork_c_upstream_diff.sh
```

## 2. Primary fork-owned or fork-extended C/C++ files

Aligned with [maint/FORK-FILES.md](../../maint/FORK-FILES.md) and `[nmap-xyberpix]` **CHANGELOG** entries.

| Path | Security-relevant role |
|------|-------------------------|
| **siem_log.cc**, **siem_log.h** | NDJSON/syslog: `json_escape`, `popen` to fixed `logger` commands, `--siem-log` paths, argv caps (`SIEM_MAX_ARGS_UTF8_BYTES`). |
| **nmap.cc**, **nmap.h** | SIEM init, long options, argv/privilege intersections. |
| **nmap_opt.cc** | New flags: validate values before network/file use. |
| **output.cc** | SIEM hooks; user-visible and log data paths. |
| **service_scan.cc** | TLS fingerprint / tlsfp; probe response handling. |
| **scan_adaptive.c**, **timing.cc**, **targets.cc**, **tcpip.cc**, **scan_engine.cc** | Adaptive/decoy timing—re-check bounds on new logic. |
| **ssh_bounce.cc** | `execvp("ssh", argv)`—keep argv free of injection; review with any bounce-option change. |
| **nfuzz/nfuzz.c** (and **nfuzz/*.c**) | Raw sockets, HTTP daemon, `execvp` browser; caps and authorization. |
| **main.cc** | Argv/command assembly (e.g. `strcat` patterns)—overflow risk on changes. |

**Note:** Older notes may say `siem_log.c`; this tree uses **siem_log.cc**—prefer the `.cc` name in reviews and patches.

## 3. What to check in each fork hunk

1. **Trust boundaries:** network, files, env, options.
2. **Memory:** `memcpy`/`strcpy`/`snprintf` discipline; integer overflow before alloc.
3. **Subprocess:** new `exec*` / `popen` / `system`—no untrusted string concatenation.
4. **Logging:** new SIEM/syslog fields escaped like existing JSON.
5. **Privilege:** new root/capability assumptions.

## 4. Helpers

```bash
grep -n 'execvp\|execl\|popen' siem_log.cc ssh_bounce.cc nfuzz/nfuzz.c 2>/dev/null
./maint/security_audit_static_grep.sh
```

## 5. Related

- [CODE-AUDIT-C-NSE-FULL-SCAN.md](CODE-AUDIT-C-NSE-FULL-SCAN.md)
- [SECURITY-OVERVIEW.md](SECURITY-OVERVIEW.md)
- [OPERATORS.md](OPERATORS.md)
