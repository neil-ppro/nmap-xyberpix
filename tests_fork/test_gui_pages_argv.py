"""PySide6 page tests: argv assembly errors surface as ArgvAssemblyError."""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import QSettings

from xyberpix_gui.argv_utils import ArgvAssemblyError
from xyberpix_gui.pages.nfuzz import NfuzzPage
from xyberpix_gui.pages.nmap import NmapPage
from xyberpix_gui.pages.nxytools import NxytoolsPage


def test_nmap_page_extra_invalid_quoting(qtbot) -> None:
    settings = QSettings("XyberPixTests", "NmapArgv")
    settings.clear()
    page = NmapPage(lambda _tool: "/nonexistent/nmap", settings)
    qtbot.addWidget(page)
    page._lines["targets"].setText("192.0.2.1")
    page._lines["extra"].setText('foo "unclosed')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()


def test_nmap_page_targets_invalid_quoting(qtbot) -> None:
    settings = QSettings("XyberPixTests", "NmapArgv2")
    settings.clear()
    page = NmapPage(lambda _tool: "/nonexistent/nmap", settings)
    qtbot.addWidget(page)
    page._lines["targets"].setText('192.0.2.1 "bad')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()


def test_nxytools_page_banner_extra_invalid_quoting(qtbot) -> None:
    page = NxytoolsPage(lambda _tool: "/nonexistent/nxy-banner")
    qtbot.addWidget(page)
    page._tabs.setCurrentIndex(0)
    page._b_host.setText("127.0.0.1")
    page._b_extra.setText('"unclosed')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()


def test_nfuzz_page_raw_extra_invalid_quoting(qtbot) -> None:
    page = NfuzzPage(lambda _tool: "/nonexistent/nfuzz")
    qtbot.addWidget(page)
    page._tabs.setCurrentIndex(0)
    page._raw_extra.setText('"unclosed')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()


def test_ncat_page_listen_extra_invalid(qtbot) -> None:
    from xyberpix_gui.pages.ncat import NcatPage

    page = NcatPage(lambda _tool: "/nonexistent/ncat")
    qtbot.addWidget(page)
    page._tabs.setCurrentIndex(0)
    page._l_extra.setText('"bad')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()


def test_nping_page_extra_invalid(qtbot) -> None:
    from xyberpix_gui.pages.nping import NpingPage

    page = NpingPage(lambda _tool: "/nonexistent/nping")
    qtbot.addWidget(page)
    page._target.setText("192.0.2.1")
    page._extra.setText('"bad')
    with pytest.raises(ArgvAssemblyError):
        page._build_args()
