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
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from xyberpix_gui.argv_utils import ArgvAssemblyError, extend_argv_from_fragment, validate_argv_list
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
        self._raw_extra.setPlaceholderText(
            "e.g. --template icmp-echo --payload-len 64 (split with shlex; no shell)"
        )
        self._lab_preset = QComboBox()
        self._lab_preset.addItem("Lab preset: off", "")
        self._lab_preset.addItem("Polite stream (rate cap + audit tag)", "polite_stream")
        self._lab_preset.addItem("Slow TCP chunks (lab warning; --proto tcp)", "slow_tcp")
        self._lab_preset.addItem("PCAP base + polite rate (set path below)", "pcap_polite")
        self._pcap_path = QLineEdit()
        self._pcap_path.setPlaceholderText("For PCAP preset: path to .pcap (IPv4)")
        self._lab_audit_tag = QLineEdit()
        self._lab_audit_tag.setPlaceholderText("Optional --lab-audit-tag (A-Za-z0-9._-)")
        rf = QFormLayout(raw)
        rf.addRow("Template / mode", self._tpl)
        rf.addRow("Destination host", self._host)
        rf.addRow("Destination port", self._dport)
        rf.addRow("Source port (0=auto)", self._sport)
        rf.addRow("Lab preset", self._lab_preset)
        rf.addRow("PCAP file", self._pcap_path)
        rf.addRow("Lab audit tag", self._lab_audit_tag)
        rf.addRow("Extra args", self._raw_extra)
        tabs.addTab(raw, "Raw / template")

        http = QWidget()
        self._http_url = QLineEdit()
        self._http_url.setPlaceholderText("http://127.0.0.1:8080/")
        self._http_extra = QLineEdit()
        self._http_extra.setPlaceholderText("Daemon / browser flags (shlex-split; QProcess, no shell)")
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

    def apply_handoff_argv(self, fragment: str) -> None:
        """Fill stream-oriented nfuzz args from Nmap handoff (user still clicks Run)."""
        self._tabs.setCurrentIndex(0)
        self._raw_extra.setText(fragment.strip())

    def _lab_preset_tail(self, key: str) -> tuple[list[str], str | None]:
        """Extra argv after base (no --pcap path here). Returns (argv, default_audit_tag)."""
        tag = self._lab_audit_tag.text().strip()
        out: list[str] = []
        default_tag: str | None = None
        if key == "polite_stream":
            out.extend(["-r", "10", "-c", "220", "-S", "random_byte", "--proto-payload-len", "256"])
            default_tag = "xyberpix_polite_stream"
        elif key == "slow_tcp":
            out.extend(["--lab-slow-tcp-send", "-r", "2", "-c", "60"])
            default_tag = "xyberpix_slow_tcp"
        elif key == "pcap_polite":
            out.extend(["-r", "6", "-c", "120", "-S", "bitflip"])
            default_tag = "xyberpix_pcap_polite"
        use_tag = tag or default_tag
        if use_tag:
            out.extend(["--lab-audit-tag", use_tag])
        return out, default_tag

    def _build_args(self) -> list[str]:
        if self._tabs.currentIndex() == 0:
            args: list[str] = []
            ex = self._raw_extra.text().strip()
            preset_key = self._lab_preset.currentData()
            pcap_mode = (
                isinstance(preset_key, str)
                and preset_key == "pcap_polite"
                and self._pcap_path.text().strip()
            )
            if ex:
                extend_argv_from_fragment(args, ex, what="nfuzz extra args")
            elif pcap_mode:
                p = self._pcap_path.text().strip()
                args.extend(["--pcap", p, "--pcap-index", "1"])
                h = self._host.text().strip()
                if h:
                    args.extend(["--dst", h])
                args.extend(["--dport", str(self._dport.value())])
                if self._sport.value() > 0:
                    args.extend(["--sport", str(self._sport.value())])
                tail, _ = self._lab_preset_tail("pcap_polite")
                args.extend(tail)
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
                if isinstance(preset_key, str) and preset_key in ("polite_stream", "slow_tcp"):
                    tail, _ = self._lab_preset_tail(preset_key)
                    args.extend(tail)
            validate_argv_list(args, what="nfuzz arguments")
            return args
        args = []
        ex = self._http_extra.text().strip()
        if ex:
            extend_argv_from_fragment(args, ex, what="nfuzz HTTP extra")
        validate_argv_list(args, what="nfuzz arguments")
        return args

    def _copy_cmd(self) -> None:
        exe = self._resolve("nfuzz") or "nfuzz"
        try:
            parts = self._build_args()
        except ArgvAssemblyError as e:
            QMessageBox.warning(self, "nfuzz command", e.message)
            return
        QApplication.clipboard().setText(shlex.join([exe, *parts]))

    def _run(self) -> None:
        exe = self._resolve("nfuzz")
        if not exe:
            self._runner.output.append_line("Error: nfuzz not found (build with make build-nfuzz).")
            return
        try:
            args = self._build_args()
        except ArgvAssemblyError as e:
            self._runner.output.append_line(f"Error: {e.message}")
            return
        if self._tabs.currentIndex() == 0 and not args:
            self._runner.output.append_line("Error: add extra args or fill host/template.")
            return
        self._runner.start(exe, args)
