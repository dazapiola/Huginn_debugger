"""Breakpoints panel — lists all active breakpoints with navigation and removal."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLabel,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QKeyEvent

from ui import theme


class BreakpointsPanel(QWidget):
    navigate_to = pyqtSignal(int)   # emitted on row click; main window navigates disasm

    def __init__(self, session) -> None:
        super().__init__()
        self._session = session
        self._build_ui()
        session.on_breakpoints_changed(self.refresh)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── toolbar row ──
        toolbar = QWidget()
        toolbar.setStyleSheet(f"background:{theme.BG_ALT}; border-bottom:1px solid {theme.BORDER};")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(6, 4, 6, 4)
        tl.setSpacing(6)

        self._count_label = QLabel("0 breakpoints")
        self._count_label.setStyleSheet(f"color:{theme.FG_DIM}; font-size:11px;")
        tl.addWidget(self._count_label)
        tl.addStretch()

        btn_clear = QPushButton("Clear All")
        btn_clear.setFixedHeight(22)
        btn_clear.setStyleSheet(
            f"font-size:11px; padding:0 8px;"
            f"background:{theme.BG_SURFACE}; color:{theme.FG_DIM};"
            f"border:1px solid {theme.BORDER}; border-radius:3px;"
        )
        btn_clear.clicked.connect(self._clear_all)
        tl.addWidget(btn_clear)

        layout.addWidget(toolbar)

        # ── table ──
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["", "Address", "Label"])
        self._table.setShowGrid(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)

        vh = self._table.verticalHeader()
        assert vh is not None
        vh.setVisible(False)
        vh.setDefaultSectionSize(22)

        hdr = self._table.horizontalHeader()
        assert hdr is not None
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 28)
        self._table.setColumnWidth(1, 120)

        self._table.cellClicked.connect(self._on_cell_clicked)
        layout.addWidget(self._table)

    # ── public ───────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        bps = sorted(self._session.breakpoints)
        self._table.setRowCount(len(bps))
        font = theme.mono_font()
        pc   = self._session.current_address

        for row, addr in enumerate(bps):
            is_pc = (addr == pc)
            label = self._session.labels.get(addr, "")

            dot = QTableWidgetItem("●")
            dot.setForeground(QColor(theme.COL_BP))
            dot.setFont(font)
            dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            dot.setData(Qt.ItemDataRole.UserRole, addr)

            addr_item = QTableWidgetItem(f"0x{addr:08x}")
            addr_item.setForeground(QColor(theme.COL_CURRENT if is_pc else theme.COL_ADDR))
            addr_item.setFont(font)
            addr_item.setData(Qt.ItemDataRole.UserRole, addr)

            label_item = QTableWidgetItem(label)
            label_item.setForeground(QColor(theme.GREEN if label else theme.FG_DIM))
            label_item.setFont(font)
            label_item.setData(Qt.ItemDataRole.UserRole, addr)

            for item in (dot, addr_item, label_item):
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

            self._table.setItem(row, 0, dot)
            self._table.setItem(row, 1, addr_item)
            self._table.setItem(row, 2, label_item)

        n = len(bps)
        self._count_label.setText(f"{n} breakpoint{'s' if n != 1 else ''}")

    # ── interaction ───────────────────────────────────────────────────────────

    def _on_cell_clicked(self, row: int, col: int) -> None:
        item = self._table.item(row, 1)
        if item is None:
            return
        addr = item.data(Qt.ItemDataRole.UserRole)
        if addr is None:
            return

        if col == 0:
            self._remove_bp(addr)
        else:
            self.navigate_to.emit(addr)

    def keyPressEvent(self, a0: QKeyEvent) -> None:  # type: ignore[override]
        if a0.key() == Qt.Key.Key_Delete:
            row = self._table.currentRow()
            if row >= 0:
                item = self._table.item(row, 1)
                if item:
                    addr = item.data(Qt.ItemDataRole.UserRole)
                    if addr is not None:
                        self._remove_bp(addr)
                        return
        super().keyPressEvent(a0)

    def _remove_bp(self, addr: int) -> None:
        self._session.breakpoints.discard(addr)
        try:
            self._session.backend.remove_breakpoint(addr)
        except Exception:
            pass
        self._session.notify_breakpoints_changed()

    def _clear_all(self) -> None:
        for addr in list(self._session.breakpoints):
            try:
                self._session.backend.remove_breakpoint(addr)
            except Exception:
                pass
        self._session.breakpoints.clear()
        self._session.notify_breakpoints_changed()
