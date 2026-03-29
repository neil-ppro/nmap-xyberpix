"""nxytools launchers (banner, DNS permutations, HTTP fuzz, WebSocket probe)."""

from __future__ import annotations

import shlex
from collections.abc import Callable

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDoubleSpinBox,
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

class NxytoolsPage(QWidget):
    def __init__(self, resolve: Callable[[str], str | None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._resolve = resolve

        title = QLabel("nxytools")
        title.setObjectName("title")
        sub = QLabel(
            "Small stdlib Python CLIs: TCP banner read, DNS word×domain, HTTP GET mutations, "
            "WebSocket upgrade probe. Requires --authorized (added automatically here)."
        )
        sub.setObjectName("subtitle")

        warn = QLabel(
            "Only use on hosts and networks you are permitted to test. "
            "Set binary paths under Settings if tools are not on PATH or under the repo nxytools/ directory."
        )
        warn.setObjectName("warn")
        warn.setWordWrap(True)

        tabs = QTabWidget()

        # --- nxy-banner ---
        ban = QWidget()
        self._b_host = QLineEdit()
        self._b_host.setPlaceholderText("host or IP")
        self._b_port = QSpinBox()
        self._b_port.setRange(1, 65535)
        self._b_port.setValue(80)
        self._b_ct = QDoubleSpinBox()
        self._b_ct.setRange(0.5, 120.0)
        self._b_ct.setDecimals(1)
        self._b_ct.setSingleStep(0.5)
        self._b_ct.setValue(5.0)
        self._b_rb = QSpinBox()
        self._b_rb.setRange(1, 65536)
        self._b_rb.setValue(2048)
        self._b_extra = QLineEdit()
        self._b_extra.setPlaceholderText("Extra flags (shlex-split; QProcess, no shell)")
        bf = QFormLayout(ban)
        bf.addRow("Host", self._b_host)
        bf.addRow("Port", self._b_port)
        bf.addRow("Connect timeout (s)", self._b_ct)
        bf.addRow("Read bytes max", self._b_rb)
        bf.addRow("Extra", self._b_extra)
        tabs.addTab(ban, "nxy-banner")

        # --- nxy-dnsperm ---
        dns = QWidget()
        self._d_domain = QLineEdit()
        self._d_domain.setPlaceholderText("example.com")
        self._d_words = QLineEdit()
        self._d_words.setPlaceholderText("Optional word list file path")
        self._d_max = QSpinBox()
        self._d_max.setRange(1, 5000)
        self._d_max.setValue(200)
        self._d_to = QDoubleSpinBox()
        self._d_to.setRange(0.5, 60.0)
        self._d_to.setDecimals(1)
        self._d_to.setValue(2.0)
        self._d_workers = QSpinBox()
        self._d_workers.setRange(1, 256)
        self._d_workers.setValue(8)
        self._d_extra = QLineEdit()
        self._d_extra.setPlaceholderText("Extra flags (shlex-split)")
        df = QFormLayout(dns)
        df.addRow("Base domain", self._d_domain)
        df.addRow("Word file", self._d_words)
        df.addRow("Max names", self._d_max)
        df.addRow("DNS timeout (s)", self._d_to)
        df.addRow("Workers", self._d_workers)
        df.addRow("Extra", self._d_extra)
        tabs.addTab(dns, "nxy-dnsperm")

        # --- nxy-httpfuzz ---
        http = QWidget()
        self._h_url = QLineEdit()
        self._h_url.setPlaceholderText("https://127.0.0.1:8080/")
        self._h_iter = QSpinBox()
        self._h_iter.setRange(1, 2000)
        self._h_iter.setValue(10)
        self._h_to = QDoubleSpinBox()
        self._h_to.setRange(0.5, 120.0)
        self._h_to.setDecimals(1)
        self._h_to.setValue(10.0)
        self._h_delay = QSpinBox()
        self._h_delay.setRange(0, 60_000)
        self._h_delay.setValue(50)
        self._h_delay.setSuffix(" ms")
        self._h_insecure = QCheckBox("TLS: skip verification (--insecure)")
        self._h_seed = QLineEdit()
        self._h_seed.setPlaceholderText("Optional --seed (integer)")
        self._h_extra = QLineEdit()
        self._h_extra.setPlaceholderText("Extra flags (shlex-split)")
        hf = QFormLayout(http)
        hf.addRow("URL", self._h_url)
        hf.addRow("Iterations", self._h_iter)
        hf.addRow("Timeout (s)", self._h_to)
        hf.addRow("Delay", self._h_delay)
        hf.addRow("", self._h_insecure)
        hf.addRow("Seed", self._h_seed)
        hf.addRow("Extra", self._h_extra)
        tabs.addTab(http, "nxy-httpfuzz")

        # --- nxy-wsprobe ---
        ws = QWidget()
        self._w_host = QLineEdit()
        self._w_host.setPlaceholderText("host")
        self._w_port = QSpinBox()
        self._w_port.setRange(1, 65535)
        self._w_port.setValue(80)
        self._w_path = QLineEdit()
        self._w_path.setText("/")
        self._w_tls = QCheckBox("TLS (--tls)")
        self._w_insecure = QCheckBox("Skip cert verify (--insecure)")
        self._w_to = QDoubleSpinBox()
        self._w_to.setRange(0.5, 120.0)
        self._w_to.setDecimals(1)
        self._w_to.setValue(10.0)
        self._w_extra = QLineEdit()
        self._w_extra.setPlaceholderText("Extra flags (shlex-split)")
        wf = QFormLayout(ws)
        wf.addRow("Host", self._w_host)
        wf.addRow("Port", self._w_port)
        wf.addRow("Path", self._w_path)
        wf.addRow("", self._w_tls)
        wf.addRow("", self._w_insecure)
        wf.addRow("Timeout (s)", self._w_to)
        wf.addRow("Extra", self._w_extra)
        tabs.addTab(ws, "nxy-wsprobe")

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

    def _build_args(self) -> tuple[str, list[str]]:
        idx = self._tabs.currentIndex()
        args: list[str] = ["--authorized"]
        what = "nxytools arguments"

        if idx == 0:
            h = self._b_host.text().strip()
            if not h:
                raise ArgvAssemblyError("nxy-banner: host is required.")
            args.extend(
                [
                    "--connect-timeout",
                    f"{self._b_ct.value():.1f}",
                    "--read-bytes",
                    str(self._b_rb.value()),
                    h,
                    str(self._b_port.value()),
                ]
            )
            ex = self._b_extra.text().strip()
            if ex:
                extend_argv_from_fragment(args, ex, what="nxy-banner extra")
            validate_argv_list(args, what=what)
            return "nxy-banner", args

        if idx == 1:
            dom = self._d_domain.text().strip().lower().rstrip(".")
            if not dom:
                raise ArgvAssemblyError("nxy-dnsperm: base domain is required.")
            args.extend(
                [
                    "--domain",
                    dom,
                    "--max-names",
                    str(self._d_max.value()),
                    "--dns-timeout",
                    f"{self._d_to.value():.1f}",
                    "--workers",
                    str(self._d_workers.value()),
                ]
            )
            wf = self._d_words.text().strip()
            if wf:
                args.extend(["--word-file", wf])
            ex = self._d_extra.text().strip()
            if ex:
                extend_argv_from_fragment(args, ex, what="nxy-dnsperm extra")
            validate_argv_list(args, what=what)
            return "nxy-dnsperm", args

        if idx == 2:
            url = self._h_url.text().strip()
            if not url:
                raise ArgvAssemblyError("nxy-httpfuzz: URL is required.")
            if self._h_insecure.isChecked():
                args.append("--insecure")
            args.extend(
                [
                    "--iterations",
                    str(self._h_iter.value()),
                    "--timeout",
                    f"{self._h_to.value():.1f}",
                    "--delay-ms",
                    str(self._h_delay.value()),
                ]
            )
            seed_s = self._h_seed.text().strip()
            if seed_s:
                if not seed_s.isdigit():
                    raise ArgvAssemblyError("nxy-httpfuzz: seed must be a non-negative integer.")
                args.extend(["--seed", seed_s])
            args.append(url)
            ex = self._h_extra.text().strip()
            if ex:
                extend_argv_from_fragment(args, ex, what="nxy-httpfuzz extra")
            validate_argv_list(args, what=what)
            return "nxy-httpfuzz", args

        # wsprobe
        host = self._w_host.text().strip()
        if not host:
            raise ArgvAssemblyError("nxy-wsprobe: host is required.")
        path = self._w_path.text().strip() or "/"
        if self._w_tls.isChecked():
            args.append("--tls")
        if self._w_insecure.isChecked():
            args.append("--insecure")
        args.extend(["--timeout", f"{self._w_to.value():.1f}", host, str(self._w_port.value()), path])
        ex = self._w_extra.text().strip()
        if ex:
            extend_argv_from_fragment(args, ex, what="nxy-wsprobe extra")
        validate_argv_list(args, what=what)
        return "nxy-wsprobe", args

    def _copy_cmd(self) -> None:
        try:
            tool, parts = self._build_args()
        except ArgvAssemblyError as e:
            QMessageBox.warning(self, "nxytools command", e.message)
            return
        exe = self._resolve(tool) or tool
        QApplication.clipboard().setText(shlex.join([exe, *parts]))

    def _run(self) -> None:
        try:
            tool, argv = self._build_args()
        except ArgvAssemblyError as e:
            self._runner.output.append_line(f"Error: {e.message}")
            return
        exe = self._resolve(tool)
        if not exe:
            self._runner.output.append_line(
                f"Error: {tool} not found (make build-nxytools or set path in Settings)."
            )
            return
        self._runner.start(exe, argv)
