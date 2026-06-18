"""Stack panel — shows RSP-relative words from the current stack frame."""
from __future__ import annotations
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

_ROWS = 24
_WORD = 8   # 64-bit


class StackPanel(QWidget):
    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._table = QTableWidget(_ROWS, 3)
        self._table.setHorizontalHeaderLabels(["Offset", "Address", "Value"])
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setColumnWidth(0, 60)
        self._table.setColumnWidth(1, 120)

        self._populate_empty()
        layout.addWidget(self._table)

    def _populate_empty(self) -> None:
        font = theme.mono_font()
        for row in range(_ROWS):
            for col in range(3):
                item = QTableWidgetItem("—")
                item.setForeground(QColor(theme.FG_DIM))
                item.setFont(font)
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                self._table.setItem(row, col, item)

    def clear(self) -> None:
        self._populate_empty()

    def refresh(self) -> None:
        regs = self._session.backend.get_registers()
        rsp  = regs.get("rsp") or regs.get("RSP")
        font = theme.mono_font()

        if rsp is None:
            return

        data = self._session.backend.read_memory(rsp, _ROWS * _WORD)

        for row in range(_ROWS):
            offset   = row * _WORD
            addr     = rsp + offset
            raw      = data[offset:offset + _WORD]
            val      = int.from_bytes(raw, "little") if len(raw) == _WORD else 0
            is_rsp   = (row == 0)

            offset_item = QTableWidgetItem(f"RSP+{offset:#04x}")
            offset_item.setForeground(QColor(theme.ACCENT if is_rsp else theme.FG_DIM))
            offset_item.setFont(font)

            addr_item = QTableWidgetItem(f"0x{addr:016x}")
            addr_item.setForeground(QColor(theme.COL_ADDR))
            addr_item.setFont(font)

            val_item  = QTableWidgetItem(f"0x{val:016x}")
            val_item.setForeground(QColor(theme.YELLOW if is_rsp else theme.FG))
            val_item.setFont(font)

            self._table.setItem(row, 0, offset_item)
            self._table.setItem(row, 1, addr_item)
            self._table.setItem(row, 2, val_item)
