"""Reusable widgets."""

from __future__ import annotations

from PySide6.QtCore import QProcess, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class OutputPanel(QWidget):
    """Live stdout/stderr from QProcess."""

    cleared = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setPlaceholderText("Output will appear here…")
        self._text.setMinimumHeight(200)
        font = self._text.font()
        font.setFamily("ui-monospace, SFMono-Regular, Menlo, Consolas, monospace")
        font.setPointSize(11)
        self._text.setFont(font)
        clear = QPushButton("Clear")
        clear.setObjectName("secondary")
        clear.clicked.connect(self.clear)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(clear)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._text)
        lay.addLayout(row)

    def clear(self) -> None:
        self._text.clear()
        self.cleared.emit()

    def append(self, chunk: str) -> None:
        self._text.moveCursor(self._text.textCursor().End)
        self._text.insertPlainText(chunk)
        self._text.moveCursor(self._text.textCursor().End)

    def append_line(self, line: str) -> None:
        self.append(line + "\n")


class ProcessRunner(QWidget):
    """Run a program with QProcess and stream to OutputPanel."""

    finished = Signal(int, QProcess.ExitStatus)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_out)
        self._proc.finished.connect(self._on_finished)
        self.output = OutputPanel()
        self._status = QLabel("")
        self._status.setObjectName("subtitle")
        row = QHBoxLayout()
        self._btn_run = QPushButton("Run")
        self._btn_stop = QPushButton("Stop")
        self._btn_stop.setObjectName("danger")
        self._btn_stop.setEnabled(False)
        self._btn_run.clicked.connect(self._emit_run_requested)
        self._btn_stop.clicked.connect(self.stop)
        row.addWidget(self._btn_run)
        row.addWidget(self._btn_stop)
        row.addStretch()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(row)
        lay.addWidget(self._status)
        lay.addWidget(self.output)

    run_requested = Signal()

    def _emit_run_requested(self) -> None:
        self.run_requested.emit()

    def set_running_label(self, text: str) -> None:
        self._status.setText(text)

    def start(self, program: str, args: list[str], cwd: str | None = None) -> bool:
        if self._proc.state() != QProcess.NotRunning:
            return False
        self.output.clear()
        self._btn_run.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._status.setText(f"Running: {program} {' '.join(args)}")
        self._proc.setProgram(program)
        self._proc.setArguments(args)
        if cwd:
            self._proc.setWorkingDirectory(cwd)
        self._proc.start()
        if not self._proc.waitForStarted(5000):
            self._btn_run.setEnabled(True)
            self._btn_stop.setEnabled(False)
            self._status.setText("Failed to start process (check binary path and permissions).")
            return False
        return True

    def stop(self) -> None:
        if self._proc.state() != QProcess.NotRunning:
            self._proc.kill()
            self._proc.waitForFinished(3000)

    def _on_out(self) -> None:
        data = self._proc.readAllStandardOutput()
        self.output.append(bytes(data).decode(errors="replace"))

    def _on_finished(self, code: int, status: QProcess.ExitStatus) -> None:
        self._btn_run.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._status.setText(f"Finished (exit {code}, status {status.name})")
        self.finished.emit(code, status)

    def is_running(self) -> bool:
        return self._proc.state() != QProcess.NotRunning
