#!/usr/bin/env python3
"""
Verify MCP offsec allowlist and presets stay aligned with on-disk scripts and docs.

- Parses _OFFSEC_ALLOWED_SCRIPTS from mcp-nmap-server/mcp_nmap/server.py
- Ensures scripts/<name>.nse exists for each entry
- Ensures every script name in preset --script lists appears in the allowlist
- Ensures docs/nse-offsec-scripts.md mentions each allowlisted script in its table
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SERVER_PY = REPO / "mcp-nmap-server" / "mcp_nmap" / "server.py"
DOC = REPO / "docs" / "nse-offsec-scripts.md"
SCRIPTS_DIR = REPO / "scripts"


def _frozenset_strings(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id != "frozenset":
            raise ValueError("expected frozenset(...) call")
        if len(node.args) != 1:
            raise ValueError("frozenset takes one arg")
        arg = node.args[0]
        if not isinstance(arg, (ast.Set, ast.SetComp)):
            raise ValueError("expected frozenset({...}) set literal")
        if isinstance(arg, ast.SetComp):
            raise ValueError("set comprehension not supported")
        out: set[str] = set()
        for elt in arg.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.add(elt.value)
            elif isinstance(elt, ast.Str):  # pragma: no cover
                out.add(elt.s)
            else:
                raise ValueError(f"unexpected set element: {ast.dump(elt)}")
        return out
    raise ValueError("expected frozenset call")


def parse_allowed_scripts() -> set[str]:
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name) and target.id == "_OFFSEC_ALLOWED_SCRIPTS":
                return _frozenset_strings(stmt.value)
    raise RuntimeError("_OFFSEC_ALLOWED_SCRIPTS not found")


def parse_preset_script_names(server_text: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(r'"--script"\s*,\s*"([^"]+)"', server_text):
        for part in m.group(1).split(","):
            s = part.strip()
            if s:
                names.add(s)
    return names


def main() -> int:
    if not SERVER_PY.is_file():
        print("missing server.py", file=sys.stderr)
        return 1

    text = SERVER_PY.read_text(encoding="utf-8")
    allowed = parse_allowed_scripts()
    preset_scripts = parse_preset_script_names(text)

    missing_files = sorted(s for s in allowed if not (SCRIPTS_DIR / f"{s}.nse").is_file())
    if missing_files:
        print("Allowlisted scripts missing scripts/*.nse:", missing_files, file=sys.stderr)
        return 1

    not_allowed = sorted(preset_scripts - allowed)
    if not_allowed:
        print("Preset --script names not in _OFFSEC_ALLOWED_SCRIPTS:", not_allowed, file=sys.stderr)
        return 1

    if DOC.is_file():
        doc_text = DOC.read_text(encoding="utf-8", errors="replace")
        missing_doc = sorted(s for s in allowed if f"`{s}`" not in doc_text)
        if missing_doc:
            print(
                "Allowlisted scripts not referenced in docs/nse-offsec-scripts.md (expect `name`):",
                missing_doc,
                file=sys.stderr,
            )
            return 1

    print(
        "offsec_mcp_sync_ok allowlist=%d preset_scripts=%d"
        % (len(allowed), len(preset_scripts))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
