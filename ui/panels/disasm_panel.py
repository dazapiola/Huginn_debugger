"""Disassembly panel — QTableView with a custom model over Instruction list."""
from __future__ import annotations
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableView, QHeaderView, QAbstractItemView
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, pyqtSignal
from PyQt6.QtGui import QColor
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ui import theme


_COLS   = ["", "Address", "Bytes", "Mnemonic", "Operands"]
_WIDTHS = [20, 110, 160, 90, 260]


class DisasmModel(QAbstractTableModel):
    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._rows: list = []

    def reload(self, addr: int | None = None) -> None:
        self.beginResetModel()
        if self._session.binary is not None:
            if addr is not None:
                base = addr
            elif self._session.current_address is not None:
                base = self._session.current_address
            else:
                base = self._session.binary.entry_point
            self._rows = self._session.disassemble_at(base, count=300)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(_COLS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _COLS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._rows):
            return None

        insn  = self._rows[index.row()]
        col   = index.column()
        is_bp = insn.address in self._session.breakpoints
        is_pc = insn.address == self._session.current_address

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return "●" if is_bp else ""
            if col == 1: return f"0x{insn.address:08x}"
            if col == 2: return insn.hex_bytes
            if col == 3: return insn.mnemonic
            if col == 4:
                if insn.jump_target:
                    return f"{insn.op_str}  → 0x{insn.jump_target:x}"
                return insn.op_str

        if role == Qt.ItemDataRole.ForegroundRole:
            if is_bp and col == 0: return QColor(theme.COL_BP)
            if is_pc:              return QColor(theme.COL_CURRENT)
            if col == 1:           return QColor(theme.COL_ADDR)
            if col == 2:           return QColor(theme.COL_BYTES)
            if col == 3:
                if insn.is_ret:    return QColor(theme.COL_RET)
                if insn.is_call:   return QColor(theme.COL_CALL)
                if insn.is_jump:   return QColor(theme.COL_JUMP)
                return QColor(theme.COL_MNEM)
            if col == 4:           return QColor(theme.COL_OPS)

        if role == Qt.ItemDataRole.BackgroundRole:
            if is_pc:   return QColor(theme.BG_SURFACE)
            if is_bp:   return QColor("#2a1a1a")
            return QColor(theme.BG)

        if role == Qt.ItemDataRole.FontRole:
            return theme.mono_font()

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == 0: return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        return None

    def toggle_breakpoint(self, row: int) -> None:
        if row >= len(self._rows):
            return
        addr = self._rows[row].address
        if addr in self._session.breakpoints:
            self._session.breakpoints.discard(addr)
            try:
                self._session.backend.remove_breakpoint(addr)
            except Exception:
                pass
        else:
            self._session.breakpoints.add(addr)
            try:
                self._session.backend.set_breakpoint(addr)
            except Exception:
                pass
        tl = self.index(row, 0)
        br = self.index(row, 0)
        self.dataChanged.emit(tl, br)

    def row_for_address(self, addr: int) -> int:
        for i, insn in enumerate(self._rows):
            if insn.address == addr:
                return i
        return -1


class DisasmPanel(QWidget):
    address_selected = pyqtSignal(int)   # emitted when user clicks a row

    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._model   = DisasmModel(session)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._view = QTableView()
        self._view.setModel(self._model)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setShowGrid(False)
        self._view.verticalHeader().setVisible(False)
        self._view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._view.setWordWrap(False)

        # Column widths
        for i, w in enumerate(_WIDTHS):
            self._view.setColumnWidth(i, w)
        self._view.horizontalHeader().setStretchLastSection(True)

        # Row height
        self._view.verticalHeader().setDefaultSectionSize(20)

        # Click to toggle BP
        self._view.clicked.connect(self._on_click)

        layout.addWidget(self._view)

    def refresh(self, addr: int | None = None) -> None:
        self._model.reload(addr)
        if self._session.current_address is not None:
            row = self._model.row_for_address(self._session.current_address)
            if row >= 0:
                self._view.scrollTo(self._model.index(row, 0))
                self._view.selectRow(row)

    def _on_click(self, index: QModelIndex) -> None:
        if index.column() == 0:
            self._model.toggle_breakpoint(index.row())
        elif index.row() < len(self._model._rows):
            addr = self._model._rows[index.row()].address
            self.address_selected.emit(addr)
