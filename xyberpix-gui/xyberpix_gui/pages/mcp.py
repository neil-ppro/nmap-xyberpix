"""MCP server setup helper (Cursor / editors)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from xyberpix_gui.binaries import find_repo_root


class McpPage(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        title = QLabel("MCP server")
        title.setObjectName("title")
        sub = QLabel(
            "nmap-mcp-server speaks MCP over stdio. Wire it in your editor’s MCP settings; "
            "this tab helps with paths and a starter JSON snippet."
        )
        sub.setObjectName("subtitle")

        root = find_repo_root()
        self._py = sys.executable
        self._module_dir = (root / "mcp-nmap-server") if root else Path("mcp-nmap-server")
        self._server_line = QLineEdit()
        self._server_line.setReadOnly(True)
        self._server_line.setText(str(self._module_dir.resolve()) if root else "mcp-nmap-server (set repo root)")

        venv_note = QLabel(
            "Install once: cd mcp-nmap-server && python3 -m venv .venv && .venv/bin/pip install -e ."
        )
        venv_note.setObjectName("subtitle")
        venv_note.setWordWrap(True)

        env = QGroupBox("Environment (optional)")
        ef = QFormLayout(env)
        self._nmap_path = QLineEdit()
        self._nmap_path.setPlaceholderText("Override Nmap binary if needed")
        self._data_dir = QLineEdit()
        self._data_dir.setPlaceholderText("NMAP_MCP_DATA_DIR")
        ef.addRow("Nmap path hint", self._nmap_path)
        ef.addRow("Data dir", self._data_dir)
        self._nmap_path.textChanged.connect(self._refresh_json)
        self._data_dir.textChanged.connect(self._refresh_json)

        self._json_preview = QPlainTextEdit()
        self._json_preview.setReadOnly(True)
        self._json_preview.setMaximumHeight(220)
        self._refresh_json()

        copy_json = QPushButton("Copy Cursor MCP JSON")
        copy_json.clicked.connect(self._copy_json)
        copy_cmd = QPushButton("Copy run command")
        copy_cmd.setObjectName("secondary")
        copy_cmd.clicked.connect(self._copy_cmd)

        test = QPushButton("Test import (current Python)")
        test.setObjectName("secondary")
        test.clicked.connect(self._test_import)

        row = QHBoxLayout()
        row.addWidget(copy_json)
        row.addWidget(copy_cmd)
        row.addStretch()

        lay = QVBoxLayout(self)
        lay.addWidget(title)
        lay.addWidget(sub)
        lay.addWidget(self._server_line)
        lay.addWidget(venv_note)
        lay.addWidget(env)
        lay.addWidget(self._json_preview)
        lay.addLayout(row)
        lay.addWidget(test)
        lay.addStretch()

    def _mcp_command(self) -> list[str]:
        root = find_repo_root()
        py = self._py
        if root and (root / "mcp-nmap-server" / ".venv" / "bin" / "python").is_file():
            py = str((root / "mcp-nmap-server" / ".venv" / "bin" / "python").resolve())
        return [py, "-m", "mcp_nmap.server"]

    def _cursor_config_obj(self) -> dict:
        cmd = self._mcp_command()
        env: dict[str, str] = {}
        np = self._nmap_path.text().strip()
        if np:
            env["NMAP_PATH"] = np
        dd = self._data_dir.text().strip()
        if dd:
            env["NMAP_MCP_DATA_DIR"] = dd
        return {
            "mcpServers": {
                "nmap": {
                    "command": cmd[0],
                    "args": cmd[1:],
                    "env": env,
                }
            }
        }

    def _refresh_json(self) -> None:
        self._json_preview.setPlainText(json.dumps(self._cursor_config_obj(), indent=2))

    def _copy_json(self) -> None:
        self._refresh_json()
        QApplication.clipboard().setText(self._json_preview.toPlainText())

    def _copy_cmd(self) -> None:
        import shlex

        line = shlex.join(self._mcp_command())
        QApplication.clipboard().setText(line)

    def _test_import(self) -> None:
        import subprocess

        r = subprocess.run(
            [self._py, "-c", "import mcp_nmap.server; print('ok')"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode == 0:
            self._json_preview.appendPlainText("\n# import test: OK\n")
        else:
            self._json_preview.appendPlainText(f"\n# import test failed: {r.stderr or r.stdout}\n")
