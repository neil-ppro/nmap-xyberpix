"""Ncat listen / connect."""

from __future__ import annotations

import shlex
from collections.abc import Callable

from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from xyberpix_gui.widgets import ProcessRunner


class NcatPage(QWidget):
    def __init__(self, resolve: Callable[[str], str | None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._resolve = resolve

        title = QLabel("Ncat")
        title.setObjectName("title")
        sub = QLabel("Listen for inbound connections or connect outbound; extra flags optional.")
        sub.setObjectName("subtitle")

        tabs = QTabWidget()

        listen = QWidget()
        self._l_port = QSpinBox()
        self._l_port.setRange(1, 65535)
        self._l_port.setValue(4444)
        self._l_extra = QLineEdit()
        self._l_extra.setPlaceholderText("e.g. -k --ssl -v")
        lf = QFormLayout(listen)
        lf.addRow("Listen port (-l)", self._l_port)
        lf.addRow("Extra", self._l_extra)
        tabs.addTab(listen, "Listen")

        conn = QWidget()
        self._c_host = QLineEdit()
        self._c_host.setPlaceholderText("host")
        self._c_port = QSpinBox()
        self._c_port.setRange(1, 65535)
        self._c_port.setValue(443)
        self._c_extra = QLineEdit()
        self._c_extra.setPlaceholderText("e.g. --ssl -v")
        cf = QFormLayout(conn)
        cf.addRow("Host", self._c_host)
        cf.addRow("Port", self._c_port)
        cf.addRow("Extra", self._c_extra)
        tabs.addTab(conn, "Connect")

        self._tabs = tabs

        copy = QPushButton("Copy command")
        copy.setObjectName("secondary")
        copy.clicked.connect(self._copy_cmd)

        self._runner = ProcessRunner()
        self._runner.run_requested.connect(self._run)

        top = QVBoxLayout()
        top.addWidget(title)
        top.addWidget(sub)
        top.addWidget(tabs)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch()
        top.addLayout(row)
        top.addWidget(self._runner)

        QVBoxLayout(self).addLayout(top)

    def _build_args(self) -> list[str]:
        if self._tabs.currentIndex() == 0:
            args = ["-l", str(self._l_port.value())]
            ex = self._l_extra.text().strip()
            if ex:
                args.extend(shlex.split(ex))
            return args
        args: list[str] = []
        ex = self._c_extra.text().strip()
        if ex:
            args.extend(shlex.split(ex))
        host = self._c_host.text().strip()
        port = str(self._c_port.value())
        if host:
            args.extend([host, port])
        return args

    def _copy_cmd(self) -> None:
        exe = self._resolve("ncat") or "ncat"
        QApplication.clipboard().setText(shlex.join([exe, *self._build_args()]))

    def _run(self) -> None:
        exe = self._resolve("ncat")
        if not exe:
            self._runner.output.append_line("Error: ncat not found.")
            return
        args = self._build_args()
        if self._tabs.currentIndex() == 1 and not self._c_host.text().strip():
            self._runner.output.append_line("Error: enter host for connect mode.")
            return
        self._runner.start(exe, args)
