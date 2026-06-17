"""Registers panel — shows CPU registers, highlights changed values."""
from __future__ import annotations
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

# x86_64 register display order
_REGS_X64 = [
    ("RAX", "RBX", "RCX", "RDX"),
    ("RSI", "RDI", "RBP", "RSP"),
    ("R8",  "R9",  "R10", "R11"),
    ("R12", "R13", "R14", "R15"),
    ("RIP", "RFLAGS", "CS",  "SS"),
]

class RegistersPanel(QWidget):
    def __init__(self, session) -> None:
        super().__init__()
        self._session  = session
        self._prev: dict[str, int] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._table = QTableWidget(len(_REGS_X64) * 2, 2)
        self._table.setHorizontalHeaderLabels(["Register", "Value"])
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setColumnWidth(0, 70)

        self._populate_empty()
        layout.addWidget(self._table)

    def _populate_empty(self) -> None:
        font = theme.mono_font()
        row = 0
        for reg_row in _REGS_X64:
            for reg in reg_row:
                name_item = QTableWidgetItem(reg)
                name_item.setForeground(QColor(theme.FG_DIM))
                name_item.setFont(font)
                val_item  = QTableWidgetItem("—")
                val_item.setForeground(QColor(theme.FG_DIM))
                val_item.setFont(font)
                val_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self._table.setItem(row, 0, name_item)
                self._table.setItem(row, 1, val_item)
                row += 1

    def refresh(self) -> None:
        regs = self._session.backend.get_registers()
        font = theme.mono_font()
        row  = 0
        for reg_row in _REGS_X64:
            for reg in reg_row:
                val = regs.get(reg.lower()) or regs.get(reg)
                changed = val is not None and self._prev.get(reg) != val
                colour  = QColor(theme.YELLOW) if changed else QColor(theme.FG)
                val_str = f"0x{val:016x}" if val is not None else "—"

                name_item = QTableWidgetItem(reg)
                name_item.setForeground(QColor(theme.ACCENT if reg == "RIP" else theme.FG_DIM))
                name_item.setFont(font)

                val_item  = QTableWidgetItem(val_str)
                val_item.setForeground(colour)
                val_item.setFont(font)
                val_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

                self._table.setItem(row, 0, name_item)
                self._table.setItem(row, 1, val_item)
                if val is not None:
                    self._prev[reg] = val
                row += 1
