"""Nping launcher."""

from __future__ import annotations

import shlex
from collections.abc import Callable

from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from xyberpix_gui.argv_utils import ArgvAssemblyError, extend_argv_from_fragment, validate_argv_list
from xyberpix_gui.widgets import ProcessRunner


class NpingPage(QWidget):
    def __init__(self, resolve: Callable[[str], str | None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._resolve = resolve

        title = QLabel("Nping")
        title.setObjectName("title")
        sub = QLabel("Choose probe mode; targets and counts map to common flags.")
        sub.setObjectName("subtitle")

        self._icmp = QRadioButton("ICMP echo")
        self._tcp = QRadioButton("TCP (port below)")
        self._udp = QRadioButton("UDP (port below)")
        self._icmp.setChecked(True)

        self._target = QLineEdit()
        self._target.setPlaceholderText("host or CIDR")

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(80)

        self._count = QSpinBox()
        self._count.setRange(1, 100000)
        self._count.setValue(5)

        self._extra = QLineEdit()
        self._extra.setPlaceholderText("More nping flags")

        mode = QGroupBox("Mode")
        ml = QVBoxLayout(mode)
        ml.addWidget(self._icmp)
        ml.addWidget(self._tcp)
        ml.addWidget(self._udp)

        form = QFormLayout()
        form.addRow(mode)
        form.addRow("Target(s)", self._target)
        form.addRow("TCP/UDP port", self._port)
        form.addRow("Count (-c)", self._count)
        form.addRow("Extra", self._extra)

        copy = QPushButton("Copy command")
        copy.setObjectName("secondary")
        copy.clicked.connect(self._copy_cmd)

        self._runner = ProcessRunner()
        self._runner.run_requested.connect(self._run)

        top = QVBoxLayout()
        top.addWidget(title)
        top.addWidget(sub)
        top.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch()
        top.addLayout(row)
        top.addWidget(self._runner)

        QVBoxLayout(self).addLayout(top)

    def _mode_args(self) -> list[str]:
        if self._tcp.isChecked():
            return ["--tcp", "-p", str(self._port.value())]
        if self._udp.isChecked():
            return ["--udp", "-p", str(self._port.value())]
        return ["--icmp"]

    def _build_args(self) -> list[str]:
        args: list[str] = [*self._mode_args(), "-c", str(self._count.value())]
        ex = self._extra.text().strip()
        if ex:
            extend_argv_from_fragment(args, ex, what="Nping extra")
        t = self._target.text().strip()
        if t:
            args.append(t)
        validate_argv_list(args, what="nping arguments")
        return args

    def _copy_cmd(self) -> None:
        exe = self._resolve("nping") or "nping"
        try:
            parts = self._build_args()
        except ArgvAssemblyError as e:
            QMessageBox.warning(self, "Nping command", e.message)
            return
        QApplication.clipboard().setText(shlex.join([exe, *parts]))

    def _run(self) -> None:
        exe = self._resolve("nping")
        if not exe:
            self._runner.output.append_line("Error: nping not found.")
            return
        if not self._target.text().strip():
            self._runner.output.append_line("Error: enter target(s).")
            return
        try:
            args = self._build_args()
        except ArgvAssemblyError as e:
            self._runner.output.append_line(f"Error: {e.message}")
            return
        self._runner.start(exe, args)
