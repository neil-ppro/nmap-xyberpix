"""Application stylesheet (dark, high-contrast accent)."""

APP_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #12141a;
    color: #e8eaef;
    font-size: 13px;
    font-family: system-ui, "SF Pro Text", "Segoe UI", sans-serif;
}
QListWidget {
    background-color: #1a1d26;
    border: none;
    border-radius: 10px;
    padding: 8px;
    outline: none;
}
QListWidget::item {
    padding: 12px 14px;
    border-radius: 8px;
    margin: 2px 0;
}
QListWidget::item:selected {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #3b5bdb, stop:1 #5c7cfa);
    color: #ffffff;
}
QListWidget::item:hover:!selected {
    background-color: #252a36;
}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #1e222d;
    border: 1px solid #2d3342;
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: #3b5bdb;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus {
    border-color: #5c7cfa;
}
QComboBox::drop-down {
    border: none;
    width: 28px;
}
QComboBox QAbstractItemView {
    background-color: #1e222d;
    border: 1px solid #2d3342;
    selection-background-color: #3b5bdb;
}
QPushButton {
    background-color: #3b5bdb;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #4c6ef5;
}
QPushButton:pressed {
    background-color: #364fc7;
}
QPushButton#secondary {
    background-color: #2d3342;
    color: #e8eaef;
}
QPushButton#secondary:hover {
    background-color: #3d4456;
}
QPushButton#danger {
    background-color: #c92a2a;
}
QPushButton#danger:hover {
    background-color: #e03131;
}
QCheckBox, QRadioButton {
    spacing: 8px;
}
QCheckBox::indicator, QRadioButton::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #4d5568;
    background-color: #1e222d;
}
QRadioButton::indicator {
    border-radius: 9px;
}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {
    background-color: #5c7cfa;
    border-color: #5c7cfa;
}
QGroupBox {
    font-weight: 600;
    border: 1px solid #2d3342;
    border-radius: 10px;
    margin-top: 12px;
    padding: 16px 12px 12px 12px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
    color: #aeb4c5;
}
QScrollBar:vertical {
    background: #1a1d26;
    width: 10px;
    margin: 4px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #3d4456;
    min-height: 40px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background: #5c6478;
}
QTabWidget::pane {
    border: 1px solid #2d3342;
    border-radius: 10px;
    top: -1px;
    padding: 12px;
    background-color: #161922;
}
QTabBar::tab {
    background: #1e222d;
    color: #aeb4c5;
    padding: 10px 18px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
QTabBar::tab:selected {
    background: #252a36;
    color: #ffffff;
    font-weight: 600;
}
QLabel#title {
    font-size: 22px;
    font-weight: 700;
    color: #ffffff;
}
QLabel#subtitle {
    color: #868e96;
    font-size: 13px;
}
QLabel#warn {
    color: #fcc419;
    background-color: rgba(252, 196, 25, 0.12);
    border: 1px solid rgba(252, 196, 25, 0.35);
    border-radius: 8px;
    padding: 10px 12px;
}
QFrame#card {
    background-color: #1a1d26;
    border: 1px solid #2d3342;
    border-radius: 12px;
}
"""
