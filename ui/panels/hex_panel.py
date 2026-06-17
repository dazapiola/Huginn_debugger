"""Hex dump panel — shows binary data in classic hex+ASCII layout."""
from __future__ import annotations
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPlainTextEdit, QLabel
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

_BYTES_PER_ROW = 16


def _format_hex_dump(data: bytes, base_addr: int) -> str:
    lines = []
    for offset in range(0, len(data), _BYTES_PER_ROW):
        chunk = data[offset:offset + _BYTES_PER_ROW]
        addr  = base_addr + offset
        # split into two groups of 8 for readability
        hex_left  = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_str   = f"{hex_left:<23s}  {hex_right:<23s}"
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"0x{addr:08x}  {hex_str}  |{ascii_part}|")
    return "\n".join(lines)


class HexPanel(QWidget):
    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._addr    = 0
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._label = QLabel("  No binary loaded")
        self._label.setStyleSheet(f"color: {theme.FG_DIM}; padding: 4px 8px; font-size: 11px;")

        self._text = QPlainTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(theme.mono_font())
        self._text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        layout.addWidget(self._label)
        layout.addWidget(self._text)

    def refresh(self, addr: int | None = None, size: int = 0x200) -> None:
        b = self._session.binary
        if b is None:
            return

        target = addr or self._session.current_address or b.entry_point
        self._addr = target

        data = self._session.backend.read_memory(target, size)
        self._label.setText(
            f"  {b.name}  ·  {b.fmt} {b.arch}  ·  "
            f"Showing {size} bytes from 0x{target:x}"
        )
        self._text.setPlainText(_format_hex_dump(data, target))
