"""Nmap scan builder with full option catalog and saved profiles."""

from __future__ import annotations

import shlex
from collections.abc import Callable

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from xyberpix_gui.nmap_option_catalog import COMBO_SPECS, LINE_SPECS
from xyberpix_gui.nmap_profile_store import delete_profile, get_profile, list_names, put_profile
from xyberpix_gui.widgets import ProcessRunner


class NmapPage(QWidget):
    def __init__(
        self,
        resolve: Callable[[str], str | None],
        settings: QSettings,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._resolve = resolve
        self._settings = settings
        self._combos: dict[str, QComboBox] = {}
        self._lines: dict[str, QLineEdit] = {}

        title = QLabel("Nmap")
        title.setObjectName("title")
        sub = QLabel(
            "Pick options from the menus (mirrors nmap --help). Companion fields supply values for "
            "flags that need paths or payloads. Save and reload named scan profiles below."
        )
        sub.setObjectName("subtitle")
        sub.setWordWrap(True)

        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel("Scan profile"))
        self._profile_pick = QComboBox()
        self._profile_pick.setMinimumWidth(220)
        self._profile_pick.activated.connect(self._on_profile_activated)
        profile_row.addWidget(self._profile_pick, stretch=1)
        save_p = QPushButton("Save profile…")
        save_p.clicked.connect(self._save_profile_dialog)
        del_p = QPushButton("Delete")
        del_p.setObjectName("secondary")
        del_p.clicked.connect(self._delete_profile)
        profile_row.addWidget(save_p)
        profile_row.addWidget(del_p)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inner = QWidget()
        inner_lay = QVBoxLayout(inner)
        inner_lay.setContentsMargins(0, 0, 12, 0)

        cat_box = QGroupBox("Options (dropdowns)")
        cat_form = QFormLayout(cat_box)
        cat_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        for spec in COMBO_SPECS:
            cb = QComboBox()
            cb.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
            cb.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            for disp, argv in spec.choices:
                cb.addItem(disp)
                cb.setItemData(cb.count() - 1, list(argv), Qt.UserRole)
            self._combos[spec.key] = cb
            cat_form.addRow(spec.label, cb)

        lines_box = QGroupBox("Values & targets (text fields)")
        lines_form = QFormLayout(lines_box)
        lines_form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        for key, label, _flag, ph in LINE_SPECS:
            le = QLineEdit()
            le.setPlaceholderText(ph)
            self._lines[key] = le
            lines_form.addRow(label, le)

        inner_lay.addWidget(cat_box)
        inner_lay.addWidget(lines_box)
        inner_lay.addStretch()
        scroll.setWidget(inner)

        copy = QPushButton("Copy command")
        copy.setObjectName("secondary")
        copy.clicked.connect(self._copy_cmd)

        self._runner = ProcessRunner()
        self._runner.run_requested.connect(self._run)

        top = QVBoxLayout()
        top.addWidget(title)
        top.addWidget(sub)
        top.addLayout(profile_row)
        top.addWidget(scroll, stretch=1)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch()
        top.addLayout(row)
        top.addWidget(self._runner)

        QVBoxLayout(self).addLayout(top)
        self._refresh_profile_combo(select_name=None)

    def _refresh_profile_combo(self, select_name: str | None) -> None:
        self._profile_pick.blockSignals(True)
        self._profile_pick.clear()
        self._profile_pick.addItem("— Current (unsaved) —", "")
        for name in list_names(self._settings):
            self._profile_pick.addItem(name, name)
        if select_name:
            idx = self._profile_pick.findData(select_name)
            if idx >= 0:
                self._profile_pick.setCurrentIndex(idx)
        self._profile_pick.blockSignals(False)

    def _on_profile_activated(self, index: int) -> None:
        if index <= 0:
            return
        name = self._profile_pick.itemData(index, Qt.UserRole)
        if not name or not isinstance(name, str):
            return
        state = get_profile(self._settings, name)
        if not state:
            return
        self._apply_state(state)

    def _collect_state(self) -> dict:
        return {
            "v": 2,
            "combo": {k: c.currentIndex() for k, c in self._combos.items()},
            "lines": {k: w.text() for k, w in self._lines.items()},
        }

    def _apply_state(self, state: dict) -> None:
        combo = state.get("combo") or {}
        if isinstance(combo, dict):
            for k, idx in combo.items():
                w = self._combos.get(k)
                if w is not None and isinstance(idx, int):
                    w.setCurrentIndex(max(0, min(idx, w.count() - 1)))
        lines = state.get("lines") or {}
        if isinstance(lines, dict):
            for k, txt in lines.items():
                w = self._lines.get(k)
                if w is not None and isinstance(txt, str):
                    w.setText(txt)

    def _save_profile_dialog(self) -> None:
        name, ok = QInputDialog.getText(self, "Save scan profile", "Profile name:")
        if not ok:
            return
        name = name.strip()
        if not name:
            return
        put_profile(self._settings, name, self._collect_state())
        self._refresh_profile_combo(select_name=name)
        QMessageBox.information(self, "Profile saved", f"Saved profile “{name}”.")

    def _delete_profile(self) -> None:
        idx = self._profile_pick.currentIndex()
        if idx <= 0:
            QMessageBox.information(self, "Delete profile", "Select a saved profile to delete.")
            return
        name = self._profile_pick.itemData(idx, Qt.UserRole)
        if not name or not isinstance(name, str):
            return
        if (
            QMessageBox.question(
                self,
                "Delete profile",
                f"Delete profile “{name}”?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            != QMessageBox.Yes
        ):
            return
        delete_profile(self._settings, name)
        self._profile_pick.setCurrentIndex(0)
        self._refresh_profile_combo(select_name=None)

    def _argv_from_combos(self) -> list[str]:
        args: list[str] = []
        for spec in COMBO_SPECS:
            cb = self._combos[spec.key]
            raw = cb.currentData(Qt.UserRole)
            if isinstance(raw, list):
                args.extend(str(x) for x in raw)
        # Output file: format + path
        fmt_cb = self._combos.get("output_format")
        path = self._lines["output_path"].text().strip()
        if fmt_cb and path:
            idx = fmt_cb.currentIndex()
            flag = {1: "-oN", 2: "-oX", 3: "-oG", 4: "-oA"}.get(idx)
            if flag:
                args.extend([flag, path])
        return args

    def _argv_from_lines(self) -> list[str]:
        args: list[str] = []

        def add_pair(flag: str, value: str) -> None:
            v = value.strip()
            if not v or not flag:
                return
            args.extend([flag, v])

        ports = self._lines["ports"].text().strip()
        if ports:
            args.extend(["-p", ports])

        add_pair("-iL", self._lines["input_list"].text())
        add_pair("-iR", self._lines["random_targets"].text())
        add_pair("--exclude", self._lines["exclude_hosts"].text())
        add_pair("--excludefile", self._lines["exclude_file"].text())
        add_pair("--exclude-ports", self._lines["exclude_ports"].text())
        add_pair("--dns-servers", self._lines["dns_servers"].text())
        add_pair("--scanflags", self._lines["scanflags"].text())
        z = self._lines["idle_zombie"].text().strip()
        if z:
            args.extend(["-sI", z])
        add_pair("-b", self._lines["ftp_bounce"].text())
        sc = self._lines["script_custom"].text().strip()
        if sc:
            args.extend(["--script", sc])
        add_pair("--script-args", self._lines["script_args"].text())
        add_pair("--script-args-file", self._lines["script_args_file"].text())
        add_pair("--script-help", self._lines["script_help"].text())
        add_pair("-D", self._lines["decoy"].text())
        add_pair("-S", self._lines["spoof_ip"].text())
        add_pair("-e", self._lines["iface"].text())
        add_pair("-g", self._lines["source_port"].text())
        add_pair("--proxies", self._lines["proxies"].text())
        add_pair("--ssh-bounce", self._lines["ssh_bounce"].text())
        add_pair("--ssh-bounce-port", self._lines["ssh_bounce_port"].text())
        add_pair("--data", self._lines["data_hex"].text())
        add_pair("--data-string", self._lines["data_string"].text())
        add_pair("--data-length", self._lines["data_length"].text())
        add_pair("--ip-options", self._lines["ip_options"].text())
        add_pair("--ttl", self._lines["ttl"].text())
        add_pair("--spoof-mac", self._lines["spoof_mac"].text())
        add_pair("--stylesheet", self._lines["stylesheet_path"].text())
        add_pair("--datadir", self._lines["datadir"].text())
        add_pair("--resume", self._lines["resume"].text())
        add_pair("--min-rtt-timeout", self._lines["min_rtt_custom"].text())
        add_pair("--initial-rtt-timeout", self._lines["initial_rtt_custom"].text())
        add_pair("--decoy-stagger", self._lines["decoy_stagger_usec"].text())
        add_pair("--siem-log", self._lines["siem_log"].text())
        add_pair("--siem-tag", self._lines["siem_tag"].text())

        extra = self._lines["extra"].text().strip()
        if extra:
            args.extend(shlex.split(extra))

        return args

    def _build_args(self) -> list[str]:
        args: list[str] = []
        args.extend(self._argv_from_combos())
        args.extend(self._argv_from_lines())
        targets = self._lines["targets"].text().strip()
        if targets:
            args.extend(shlex.split(targets))
        return args

    def _copy_cmd(self) -> None:
        exe = self._resolve("nmap") or "nmap"
        line = shlex.join([exe, *self._build_args()])
        QApplication.clipboard().setText(line)

    def _run(self) -> None:
        exe = self._resolve("nmap")
        if not exe:
            self._runner.output.append_line("Error: nmap not found. Set path in Settings or PATH.")
            self._runner.set_running_label("nmap not found")
            return
        if not self._lines["targets"].text().strip():
            if not self._lines["input_list"].text().strip() and not self._lines["random_targets"].text().strip():
                self._runner.output.append_line("Error: enter targets, or set Input list (-iL) / Random targets (-iR).")
                return
        args = self._build_args()
        self._runner.start(exe, args)
