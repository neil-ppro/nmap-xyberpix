# Fork maintenance (nmap-xyberpix)

How this repository relates to **upstream Nmap**, which parts are **fork-owned**, and what to re-run after merges or security-sensitive changes.

## Upstream merge procedure

1. Follow **[UPSTREAM-MERGE.md](UPSTREAM-MERGE.md)** (remotes, merge/rebase, conflict preference).
2. Use **[maint/FORK-FILES.md](../maint/FORK-FILES.md)** as a map of paths that usually need manual attention during conflicts.

## Fork-owned surface (review when touching or merging)

| Area | Location | Notes |
|------|----------|--------|
| **SIEM / CLI (C)** | `siem_log.*`, `nmap.cc`, `nmap_opt.cc`, `output.cc`, related scan/engine files | See CHANGELOG `[SIEM]` / `[nmap-xyberpix]`. |
| **MCP server** | `mcp-nmap-server/` | Policy tables, XML parsing, subprocess argv; **`pytest tests/`**. |
| **ngit** | `ngit/ngit`, `ngit/ngit.1`, install bits in `configure.ac` / `Makefile.in` | Python 3; **`pytest tests_fork/`** covers scan caps, **`parse_extra_regex`**, symlink skip, subprocess CLI. |
| **nfuzz** | `nfuzz/nfuzz.c`, `nfuzz/bt_l2cap_mac.*`, `nfuzz/nfuzz.1` | C harness; rebuild **`make build-nfuzz`**. |
| **xyberpix-gui** | `xyberpix-gui/xyberpix_gui/` | PySide6 launcher; argv assembly in **`argv_utils.py`**; covered by **`tests_fork/`**. |
| **Offsec NSE** | `scripts/*`, `nselib/http_offsec.lua`, etc. | Run **`maint/check_offsec_mcp_sync.py`**; see **docs/nse-offsec-scripts.md**. |
| **Zenmap fork UI** | `zenmap/` (option tables, profile editor) | **`maint/check_zenmap_siem_flags.py`**. |
| **Security / operator docs** | `docs/security/*` (incl. **OPERATORS.md**), this file | Keep **SECURITY-OVERVIEW** and **OPERATORS** cross-links accurate. |
| **CI** | `.github/workflows/nmap-xyberpix-checks.yml` | Add jobs here when new test suites appear. |

## Post-merge / pre-release checklist

Run from a clean build tree after resolving conflicts:

```bash
./configure
make
```

**Python / policy**

```bash
cd mcp-nmap-server && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' \
  && .venv/bin/python -m pytest tests/ -q && cd ..
python3 -m pip install -U pip
python3 -m pip install -r tests_fork/requirements-ci.txt
QT_QPA_PLATFORM=offscreen python3 -m pytest tests_fork/ -q --tb=short
pip-audit -r tests_fork/requirements-ci.txt
```

**Maintainer sync**

```bash
python3 maint/check_zenmap_siem_flags.py
python3 maint/check_offsec_mcp_sync.py
python3 maint/check_mcp_longopt_baseline.py
```

If **`nmap.cc`** long-options changed:

```bash
python3 maint/update_mcp_longopt_baseline.py
python3 maint/check_mcp_longopt_baseline.py
```

**Optional**: SIEM smoke (see CI workflow for artifact pattern). CI already runs **`make build-nfuzz`** and **`nfuzz --version`** on Ubuntu after **`make`**.

## Adding a new fork feature

1. Update **[CHANGELOG](../CHANGELOG)** (fork entries at top).
2. If operators must change behavior or env vars: **SECURITY-OVERVIEW.md**, **docs/security/OPERATORS.md**, and relevant man pages / READMEs.
3. If the feature parses untrusted input or runs subprocesses: add or extend **automated tests** (MCP `tests/`, **`tests_fork/`**, or C/unit tests as appropriate).
4. If MCP exposes new capabilities: extend **`mcp_nmap/server.py`** policy and **MCP README**; run **`maint/check_offsec_mcp_sync.py`** if NSE presets are involved.

## Regression tests for fork Python

- **`tests_fork/`** — **`ngit`** (scan caps, **`parse_extra_regex`**, symlink skip, subprocess CLI), **`xyberpix_gui.argv_utils`** / **`binaries`**, and **PySide6** argv tests for **Nmap** / **nfuzz** / **Ncat** / **Nping** pages. Pinned deps: **`tests_fork/requirements-ci.txt`**; CI runs **`pip-audit -r`** on that file.
- **`pytest.ini`** (repo root) — **`testpaths = tests_fork`**, **`qt_api = pyside6`**.
- **`mcp-nmap-server/tests/`** — MCP policy and XML safety.

Keeping **`tests_fork/`** green avoids silent breakage in **`ngit`** validation and GUI argv assembly when refactoring.
