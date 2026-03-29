"""Welcome / dashboard."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class HomePage(QWidget):
    """Card grid + open settings."""

    open_tool = Signal(int)  # stack index after home (1=nmap, …)
    open_settings = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        title = QLabel("Xyberpix")
        title.setObjectName("title")
        sub = QLabel(
            "A focused control room for Nmap, Nping, Ncat, nfuzz, nxytools, and MCP setup. "
            "Built for nmap-xyberpix."
        )
        sub.setObjectName("subtitle")
        sub.setWordWrap(True)

        gear = QPushButton("Settings…")
        gear.setObjectName("secondary")
        gear.clicked.connect(self.open_settings.emit)
        head = QHBoxLayout()
        head.addWidget(title)
        head.addStretch()
        head.addWidget(gear)

        grid = QGridLayout()
        grid.setSpacing(14)
        cards = [
            (
                "Nmap",
                "Profiles (incl. built-in checklists), SIEM fields, nfuzz handoff, ngit→SIEM line.",
                1,
            ),
            ("Nping", "Probe paths with ICMP/TCP/UDP; echo modes and timing in plain language.", 2),
            ("Ncat", "Listen or connect: pivots, TLS, and one-off netcat workflows.", 3),
            (
                "nfuzz",
                "Templates, HTTP daemon, PCAP, lab presets + audit JSON on stderr.",
                4,
            ),
            (
                "nxytools",
                "nxy-banner, nxy-dnsperm, nxy-httpfuzz, nxy-wsprobe — paths in Settings or repo nxytools/.",
                5,
            ),
            ("MCP server", "Copy Cursor config and env hints for nmap-mcp-server.", 6),
        ]
        for i, (name, blurb, idx) in enumerate(cards):
            grid.addWidget(self._card(name, blurb, idx), i // 2, i % 2)

        lay = QVBoxLayout(self)
        lay.addLayout(head)
        lay.addWidget(sub)
        lay.addSpacing(16)
        lay.addLayout(grid)
        lay.addStretch()

    def _card(self, name: str, blurb: str, stack_index: int) -> QFrame:
        f = QFrame()
        f.setObjectName("card")
        inner = QVBoxLayout(f)
        inner.setContentsMargins(18, 16, 18, 16)
        t = QLabel(name)
        t.setStyleSheet("font-size: 16px; font-weight: 700; color: #ffffff;")
        b = QLabel(blurb)
        b.setObjectName("subtitle")
        b.setWordWrap(True)
        btn = QPushButton("Open")
        btn.clicked.connect(lambda _=False, s=stack_index: self.open_tool.emit(s))
        inner.addWidget(t)
        inner.addWidget(b)
        inner.addWidget(btn)
        return f
