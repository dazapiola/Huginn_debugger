"""Log panel — shows GDB console output, program stdout, and debugger events."""
from __future__ import annotations
import sys, os
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont

from ui import theme

# kind → (prefix label, colour)
_KINDS: dict[str, tuple[str, str]] = {
    "evt": ("EVT", theme.YELLOW),
    "out": ("OUT", theme.GREEN),
    "gdb": ("GDB", theme.FG_DIM),
    "err": ("ERR", theme.RED),
}


class LogPanel(QWidget):

    # Internal signal so any thread can safely append.
    _sig = pyqtSignal(str, str)   # (message, kind)

    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._build_ui()
        self._sig.connect(self._do_append)
        session.on_log(self.append)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── toolbar ──
        toolbar = QWidget()
        toolbar.setStyleSheet(f"background:{theme.BG_ALT}; border-bottom:1px solid {theme.BORDER};")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(6, 4, 6, 4)
        tl.setSpacing(6)

        self._count = QLabel("0 lines")
        self._count.setStyleSheet(f"color:{theme.FG_DIM}; font-size:11px;")
        tl.addWidget(self._count)
        tl.addStretch()

        btn = QPushButton("Clear")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            f"font-size:11px; padding:0 8px;"
            f"background:{theme.BG_SURFACE}; color:{theme.FG_DIM};"
            f"border:1px solid {theme.BORDER}; border-radius:3px;"
        )
        btn.clicked.connect(self._clear)
        tl.addWidget(btn)
        layout.addWidget(toolbar)

        # ── text area ──
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(theme.mono_font(10))
        self._text.setStyleSheet(
            f"background:{theme.BG}; color:{theme.FG}; border:none;"
            f"selection-background-color:{theme.BG_SURFACE};"
        )
        doc = self._text.document()
        assert doc is not None
        doc.setMaximumBlockCount(2000)
        layout.addWidget(self._text)

        self._line_count = 0

    # ── public ───────────────────────────────────────────────────────────────

    def append(self, msg: str, kind: str = "evt") -> None:
        """Thread-safe: can be called from any thread."""
        self._sig.emit(msg, kind)

    # ── internal ─────────────────────────────────────────────────────────────

    def _do_append(self, msg: str, kind: str) -> None:
        label, colour = _KINDS.get(kind, ("LOG", theme.FG))
        ts = datetime.now().strftime("%H:%M:%S")

        cursor = self._text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # timestamp — dim
        _insert(cursor, f"{ts} ", theme.FG_DIM)
        # kind badge
        _insert(cursor, f"{label} ", colour, bold=True)
        # message
        _insert(cursor, msg + "\n", colour if kind != "gdb" else theme.FG_DIM)

        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()

        self._line_count += 1
        self._count.setText(f"{self._line_count} line{'s' if self._line_count != 1 else ''}")

    def _clear(self) -> None:
        self._text.clear()
        self._line_count = 0
        self._count.setText("0 lines")


def _insert(cursor: QTextCursor, text: str, colour: str, bold: bool = False) -> None:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(colour))
    if bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    cursor.setCharFormat(fmt)
    cursor.insertText(text)
