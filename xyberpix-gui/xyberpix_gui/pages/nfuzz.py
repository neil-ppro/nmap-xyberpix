"""nfuzz raw / HTTP-oriented launcher."""

from __future__ import annotations

import shlex
from collections.abc import Callable
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
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


class NfuzzPage(QWidget):
    def __init__(self, resolve: Callable[[str], str | None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._resolve = resolve

        title = QLabel("nfuzz")
        title.setObjectName("title")
        sub = QLabel("Fuzzing and HTTP daemon modes. Only use on networks you own or are authorized to test.")
        sub.setObjectName("subtitle")

        warn = QLabel(
            "Reminder: use --authorized on raw sends when required; follow your org’s rules and local law."
        )
        warn.setObjectName("warn")
        warn.setWordWrap(True)

        tabs = QTabWidget()

        raw = QWidget()
        self._tpl = QComboBox()
        self._tpl.setEditable(True)
        self._tpl.addItems(["icmp-echo", "tcp-syn", "udp"])
        self._host = QLineEdit()
        self._host.setPlaceholderText("--dst or target host")
        self._dport = QSpinBox()
        self._dport.setRange(1, 65535)
        self._dport.setValue(80)
        self._sport = QSpinBox()
        self._sport.setRange(0, 65535)
        self._sport.setValue(0)
        self._sport.setSpecialValueText("auto")
        self._raw_extra = QLineEdit()
        self._raw_extra.setPlaceholderText("e.g. --template icmp-echo --payload-len 64")
        rf = QFormLayout(raw)
        rf.addRow("Template / mode", self._tpl)
        rf.addRow("Destination host", self._host)
        rf.addRow("Destination port", self._dport)
        rf.addRow("Source port (0=auto)", self._sport)
        rf.addRow("Extra args", self._raw_extra)
        tabs.addTab(raw, "Raw / template")

        http = QWidget()
        self._http_url = QLineEdit()
        self._http_url.setPlaceholderText("http://127.0.0.1:8080/")
        self._http_extra = QLineEdit()
        self._http_extra.setPlaceholderText("Daemon / browser flags per nfuzz(1)")
        hf = QFormLayout(http)
        hf.addRow("Base URL (if applicable)", self._http_url)
        hf.addRow("Extra", self._http_extra)
        tabs.addTab(http, "HTTP / daemon")

        self._tabs = tabs

        copy = QPushButton("Copy command")
        copy.setObjectName("secondary")
        copy.clicked.connect(self._copy_cmd)

        self._runner = ProcessRunner()
        self._runner.run_requested.connect(self._run)

        top = QVBoxLayout()
        top.addWidget(title)
        top.addWidget(sub)
        top.addWidget(warn)
        top.addWidget(tabs)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch()
        top.addLayout(row)
        top.addWidget(self._runner)

        QVBoxLayout(self).addLayout(top)

    def _build_args(self) -> list[str]:
        if self._tabs.currentIndex() == 0:
            args: list[str] = []
            ex = self._raw_extra.text().strip()
            if ex:
                args.extend(shlex.split(ex))
            else:
                tpl = self._tpl.currentText().strip()
                if tpl:
                    args.extend(["--template", tpl])
                h = self._host.text().strip()
                if h:
                    args.extend(["--dst", h])
                args.extend(["--dport", str(self._dport.value())])
                if self._sport.value() > 0:
                    args.extend(["--sport", str(self._sport.value())])
            return args
        args = []
        ex = self._http_extra.text().strip()
        if ex:
            args.extend(shlex.split(ex))
        return args

    def _copy_cmd(self) -> None:
        exe = self._resolve("nfuzz") or "nfuzz"
        QApplication.clipboard().setText(shlex.join([exe, *self._build_args()]))

    def _run(self) -> None:
        exe = self._resolve("nfuzz")
        if not exe:
            self._runner.output.append_line("Error: nfuzz not found (build with make build-nfuzz).")
            return
        args = self._build_args()
        if self._tabs.currentIndex() == 0 and not args:
            self._runner.output.append_line("Error: add extra args or fill host/template.")
            return
        self._runner.start(exe, args)
