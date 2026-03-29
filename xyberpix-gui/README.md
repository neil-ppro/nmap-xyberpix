# Xyberpix GUI

A modern PySide6 desktop app for **nmap-xyberpix**: run **Nmap**, **Nping**, **Ncat**, and **nfuzz** with guided forms, live output, and quick setup for **mcp-nmap-server** (Cursor / MCP clients).

## Install

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## Run

```bash
xyberpix-gui
# or
python -m xyberpix_gui
```

## Nmap tab

Options follow **`nmap --help`** sections as dropdowns, with text fields for flags that need values (ports, files, `-D`, `--script`, SIEM paths, etc.). Use **Save profile…** to store the whole form under a name (stored in Qt settings as `nmap/profiles_v2`); pick a profile from the menu to load it.

## Binary paths

The app looks for tools on `PATH`, or under **`NMAP_XYBERPIX_ROOT`** (path to the nmap-xyberpix source tree) for freshly built binaries (`nmap/nmap`, `nping/nping`, `ncat/ncat`, `nfuzz/nfuzz`).

Override individual tools in **Settings** (gear on the welcome screen) if needed.

## MCP server

The **MCP** tab copies a sample Cursor MCP config and documents `pip install -e ./mcp-nmap-server` and safety env vars. The GUI does not replace your editor’s MCP wiring; it helps you configure it correctly.

## Tests (repository root)

**`argv_utils`** and **PySide6** page argv tests live under **`tests_fork/`** in the parent tree. From the repo root:

```bash
python3 -m pip install -U pip
python3 -m pip install -r tests_fork/requirements-ci.txt
QT_QPA_PLATFORM=offscreen python3 -m pytest tests_fork/ -q
pip-audit -r tests_fork/requirements-ci.txt
```

Optional: `pip install -e ".[dev]"` here includes **pytest** for ad-hoc runs. See **`docs/FORK-MAINTENANCE.md`** and **`docs/security/OPERATORS.md`**.
