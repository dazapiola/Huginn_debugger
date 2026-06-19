"""Hex dump panel — shows binary data in classic hex+ASCII layout."""
from __future__ import annotations
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

_BYTES_PER_ROW = 16


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

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Address", "Hex", "ASCII"])
        self._table.setShowGrid(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self._table.setFont(theme.mono_font())

        vh = self._table.verticalHeader()
        assert vh is not None
        vh.setVisible(False)
        vh.setDefaultSectionSize(18)

        hdr = self._table.horizontalHeader()
        assert hdr is not None
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 148)   # 0x0000000000401000
        self._table.setColumnWidth(1, 408)   # 16 bytes × "xx " + middle gap

        layout.addWidget(self._label)
        layout.addWidget(self._table)

    def refresh(self, addr: int | None = None, size: int = 0x200) -> None:
        b = self._session.binary
        if b is None:
            return

        target = addr or self._session.current_address or b.entry_point
        self._addr = target

        data = self._session.backend.read_memory(target, size)
        self._label.setText(
            f"  {b.name}  ·  {b.fmt} {b.arch}  ·  "
            f"Showing {size:#x} bytes from {target:#x}"
        )

        font = theme.mono_font()
        col_addr  = QColor(theme.COL_ADDR)
        col_hex   = QColor(theme.FG)
        col_ascii = QColor(theme.FG_DIM)

        rows = []
        for offset in range(0, len(data), _BYTES_PER_ROW):
            chunk = data[offset:offset + _BYTES_PER_ROW]
            row_addr  = target + offset
            hex_left  = " ".join(f"{byte:02x}" for byte in chunk[:8])
            hex_right = " ".join(f"{byte:02x}" for byte in chunk[8:])
            hex_str   = f"{hex_left:<23}  {hex_right}"
            ascii_str = "".join(chr(byte) if 0x20 <= byte < 0x7f else "." for byte in chunk)
            rows.append((row_addr, hex_str, ascii_str))

        self._table.setRowCount(len(rows))
        for row_idx, (row_addr, hex_str, ascii_str) in enumerate(rows):
            addr_item  = QTableWidgetItem(f"0x{row_addr:016x}")
            hex_item   = QTableWidgetItem(hex_str)
            ascii_item = QTableWidgetItem(ascii_str)

            for item, color in (
                (addr_item,  col_addr),
                (hex_item,   col_hex),
                (ascii_item, col_ascii),
            ):
                item.setFont(font)
                item.setForeground(color)
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

            self._table.setItem(row_idx, 0, addr_item)
            self._table.setItem(row_idx, 1, hex_item)
            self._table.setItem(row_idx, 2, ascii_item)
