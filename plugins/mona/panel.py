"""Mona panel — QDockWidget providing mona.py command access."""
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QPlainTextEdit,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from ui import theme


class _MonaWorker(QThread):
    output = pyqtSignal(str)
    done = pyqtSignal()

    def __init__(self, cmd_args: list[str], session, parent=None) -> None:
        super().__init__(parent)
        self._cmd_args = cmd_args
        self._session = session

    def run(self) -> None:
        from plugins.mona.bridge import get_mona, MonaBridge

        def _log(msg: str) -> None:
            self.output.emit(msg)

        try:
            m = get_mona()
            m.dbg = MonaBridge(self._session, _log)
            m.arch = 64
            m.main(self._cmd_args)
        except Exception as exc:
            self.output.emit(f"[mona error] {exc}")
        finally:
            self.done.emit()


class MonaPanel(QDockWidget):
    def __init__(self, session, parent=None) -> None:
        super().__init__("Mona", parent)
        self._session = session
        self._worker: _MonaWorker | None = None
        self._build_ui()
        self.setAllowedAreas(Qt.DockWidgetArea.AllDockWidgetAreas)
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable |
            QDockWidget.DockWidgetFeature.DockWidgetClosable
        )

    def _build_ui(self) -> None:
        root = QWidget()
        self.setWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Output area
        self._output = QPlainTextEdit()
        self._output.setReadOnly(True)
        self._output.setFont(theme.mono_font())
        self._output.setStyleSheet(
            f"background:{theme.BG}; color:{theme.FG};"
            f" border:1px solid {theme.BG_SURFACE};"
        )
        layout.addWidget(self._output)

        # Quick buttons
        btn_row = QHBoxLayout()
        _btn_style = (
            f"background:{theme.BG_SURFACE}; color:{theme.FG};"
            " border:none; padding:3px 8px;"
        )
        for label, cmd in [
            ("Pattern Create 200", "pattern_create 200"),
            ("Bytearray (no 0x00)", "bytearray -cpb 0x00"),
            ("Pattern Offset (RIP)", ""),
        ]:
            btn = QPushButton(label)
            btn.setStyleSheet(_btn_style)
            if cmd:
                btn.clicked.connect(lambda _, c=cmd: self._fill_and_run(c))
            else:
                btn.clicked.connect(self._fill_offset_from_rip)
            btn_row.addWidget(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Command input row
        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText(
            "mona command  (e.g. bytearray -cpb 0x00 0x0a)"
        )
        self._input.setFont(theme.mono_font())
        self._input.setStyleSheet(
            f"background:{theme.BG_SURFACE}; color:{theme.FG};"
            " border:none; padding:2px 6px;"
        )
        self._input.returnPressed.connect(self._run_cmd)
        input_row.addWidget(self._input, 1)

        self._run_btn = QPushButton("Run")
        self._run_btn.setStyleSheet(
            f"background:{theme.ACCENT}; color:{theme.BG};"
            " border:none; padding:3px 10px; font-weight:600;"
        )
        self._run_btn.clicked.connect(self._run_cmd)
        input_row.addWidget(self._run_btn)

        clr_btn = QPushButton("Clear")
        clr_btn.setStyleSheet(_btn_style)
        clr_btn.clicked.connect(self._output.clear)
        input_row.addWidget(clr_btn)
        layout.addLayout(input_row)

    def _fill_and_run(self, cmd: str) -> None:
        self._input.setText(cmd)
        self._run_cmd()

    def _fill_offset_from_rip(self) -> None:
        rip = None
        try:
            regs = self._session.backend.get_registers()
            rip = regs.get("rip") or regs.get("RIP")
        except Exception:
            pass
        if rip:
            self._input.setText(f"pattern_offset {hex(rip)}")
        else:
            self._input.setText("pattern_offset ")
        self._input.setFocus()

    def _run_cmd(self) -> None:
        cmd = self._input.text().strip()
        if not cmd:
            return
        if self._worker and self._worker.isRunning():
            return

        self._output.appendPlainText(f"\n>>> mona {cmd}")
        self._worker = _MonaWorker(cmd.split(), self._session, self)
        self._worker.output.connect(self._output.appendPlainText)
        self._worker.done.connect(self._on_done)
        self._run_btn.setEnabled(False)
        self._worker.start()

    def _on_done(self) -> None:
        self._run_btn.setEnabled(True)
        self._worker = None
