"""Main shell: sidebar + stacked pages."""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from xyberpix_gui.binaries import find_repo_root, resolve_binary
from xyberpix_gui.pages import HomePage, McpPage, NcatPage, NfuzzPage, NmapPage, NpingPage


class ToolResolver:
    """Callable that resolves tool paths using current QSettings (no stale closure)."""

    def __init__(self, settings: QSettings) -> None:
        self._settings = settings

    def __call__(self, tool: str) -> str | None:
        saved_repo = self._settings.value("repo_root", "", str).strip()
        if saved_repo:
            os.environ["NMAP_XYBERPIX_ROOT"] = str(Path(saved_repo).expanduser())
        ov = self._settings.value(f"paths/{tool}", "", str).strip() or None
        return resolve_binary(tool, ov)


class SettingsDialog(QDialog):
    def __init__(self, settings: QSettings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Binary paths")
        self.setMinimumWidth(520)
        self._settings = settings
        form = QFormLayout()
        self._fields: dict[str, QLineEdit] = {}
        for key, label in (
            ("nmap", "nmap"),
            ("nping", "nping"),
            ("ncat", "ncat"),
            ("nfuzz", "nfuzz"),
            ("ngit", "ngit"),
        ):
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            le = QLineEdit()
            le.setText(self._settings.value(f"paths/{key}", "", str))
            le.setPlaceholderText("Leave empty for PATH / repo auto-detect")
            btn = QPushButton("Browse…")
            btn.setObjectName("secondary")
            btn.clicked.connect(lambda _=False, e=le: self._browse(e))
            h.addWidget(le)
            h.addWidget(btn)
            self._fields[key] = le
            form.addRow(label, row)
        repo = QLineEdit()
        repo.setText(self._settings.value("repo_root", "", str))
        rr = find_repo_root()
        repo.setPlaceholderText(f"Optional override (detected: {rr})" if rr else "Optional: path to nmap-xyberpix tree")
        form.addRow("Repo root", repo)
        self._repo = repo
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(bb)

    def _browse(self, le: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select binary", "", "All (*)")
        if path:
            le.setText(path)

    def _save(self) -> None:
        for key, le in self._fields.items():
            self._settings.setValue(f"paths/{key}", le.text().strip())
        self._settings.setValue("repo_root", self._repo.text().strip())
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Xyberpix")
        self.setMinimumSize(960, 640)
        self.resize(1100, 720)

        self._settings = QSettings("Xyberpix", "GUI")
        self._resolver = ToolResolver(self._settings)

        side = QListWidget()
        side.setFocusPolicy(Qt.StrongFocus)
        for text, tip in (
            ("Home", "Overview"),
            ("Nmap", "Scan builder"),
            ("Nping", "Probes & echo"),
            ("Ncat", "Listen / connect"),
            ("nfuzz", "Fuzzing"),
            ("MCP", "Editor integration"),
        ):
            it = QListWidgetItem(text)
            it.setToolTip(tip)
            side.addItem(it)
        side.setCurrentRow(0)
        side.setFixedWidth(210)

        stack = QStackedWidget()
        home = HomePage()
        home.open_tool.connect(stack.setCurrentIndex)
        home.open_settings.connect(self._open_settings)
        stack.addWidget(home)
        nfuzz = NfuzzPage(self._resolver)
        stack.addWidget(
            NmapPage(
                self._resolver,
                self._settings,
                on_nfuzz_handoff=nfuzz.apply_handoff_argv,
                focus_nfuzz_sidebar=lambda: side.setCurrentRow(4),
            )
        )
        stack.addWidget(NpingPage(self._resolver))
        stack.addWidget(NcatPage(self._resolver))
        stack.addWidget(nfuzz)
        stack.addWidget(McpPage())

        side.currentRowChanged.connect(stack.setCurrentIndex)

        central = QWidget()
        h = QHBoxLayout(central)
        h.setContentsMargins(16, 16, 16, 16)
        h.setSpacing(16)
        h.addWidget(side)
        h.addWidget(stack, stretch=1)
        self.setCentralWidget(central)

    def _open_settings(self) -> None:
        if SettingsDialog(self._settings, self).exec() == QDialog.Accepted:
            QMessageBox.information(
                self,
                "Settings saved",
                "New binary paths and repo root apply the next time you run a tool.",
            )
