"""Registers panel — shows CPU registers in a compact 4-column layout."""
from __future__ import annotations
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme

# Each tuple is (left_reg, right_reg) — displayed in two columns side by side.
# Total: 10 rows × 2 registers = 20 registers.
_REG_PAIRS = [
    ("RAX",    "RBX"),
    ("RCX",    "RDX"),
    ("RSI",    "RDI"),
    ("RBP",    "RSP"),
    ("R8",     "R9"),
    ("R10",    "R11"),
    ("R12",    "R13"),
    ("R14",    "R15"),
    ("RIP",    "RFLAGS"),
    ("CS",     "SS"),
]

_COL_NAME_L = 0
_COL_VAL_L  = 1
_COL_NAME_R = 2
_COL_VAL_R  = 3


def _get(regs: dict, name: str):
    """Return register value, checking both lowercase and uppercase keys.
    Returns None only when the key is genuinely absent — NOT when value is 0.
    """
    v = regs.get(name.lower())
    if v is not None:
        return v
    return regs.get(name)


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

        self._table = QTableWidget(len(_REG_PAIRS), 4)
        self._table.setHorizontalHeaderLabels(["Reg", "Value", "Reg", "Value"])
        self._table.verticalHeader().setVisible(False)
        self._table.setShowGrid(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.verticalHeader().setDefaultSectionSize(20)
        self._table.setColumnWidth(_COL_NAME_L, 65)
        self._table.setColumnWidth(_COL_VAL_L,  145)
        self._table.setColumnWidth(_COL_NAME_R, 65)
        # COL_VAL_R stretches to fill

        self._populate_empty()
        layout.addWidget(self._table)

    def _make_name_item(self, name: str) -> QTableWidgetItem:
        item = QTableWidgetItem(name)
        colour = theme.ACCENT if name == "RIP" else theme.FG_DIM
        item.setForeground(QColor(colour))
        item.setFont(theme.mono_font())
        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return item

    def _make_val_item(self, text: str, colour: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setForeground(QColor(colour))
        item.setFont(theme.mono_font())
        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return item

    def _populate_empty(self) -> None:
        for row, (left, right) in enumerate(_REG_PAIRS):
            self._table.setItem(row, _COL_NAME_L, self._make_name_item(left))
            self._table.setItem(row, _COL_VAL_L,  self._make_val_item("—", theme.FG_DIM))
            self._table.setItem(row, _COL_NAME_R, self._make_name_item(right))
            self._table.setItem(row, _COL_VAL_R,  self._make_val_item("—", theme.FG_DIM))

    def refresh(self) -> None:
        regs = self._session.backend.get_registers()
        for row, (left, right) in enumerate(_REG_PAIRS):
            self._update_cell(row, _COL_NAME_L, _COL_VAL_L, left,  regs)
            self._update_cell(row, _COL_NAME_R, _COL_VAL_R, right, regs)

    def _update_cell(self, row: int, col_name: int, col_val: int,
                     reg: str, regs: dict) -> None:
        val = _get(regs, reg)
        changed = val is not None and self._prev.get(reg) != val
        colour  = theme.YELLOW if changed else (theme.FG if val is not None else theme.FG_DIM)
        val_str = f"0x{val:016x}" if val is not None else "—"

        self._table.setItem(row, col_name, self._make_name_item(reg))
        self._table.setItem(row, col_val,  self._make_val_item(val_str, colour))

        if val is not None:
            self._prev[reg] = val
