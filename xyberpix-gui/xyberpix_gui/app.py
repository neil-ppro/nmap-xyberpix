"""Application entry."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from xyberpix_gui.main_window import MainWindow
from xyberpix_gui.theme import APP_STYLESHEET


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Xyberpix")
    app.setOrganizationName("Xyberpix")
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLESHEET)
    w = MainWindow()
    w.show()
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()
