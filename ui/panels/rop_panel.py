"""ROP Panel — shows ROP/JOP/SYS gadgets found by ROPgadget, filterable."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLabel, QLineEdit, QComboBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QColor

from ui import theme

_KIND_COLORS = {
    "ROP": theme.COL_RET,
    "JOP": theme.COL_JUMP,
    "SYS": theme.MAUVE,
    "???": theme.FG_DIM,
}


class ROPPanel(QWidget):
    navigate_to = pyqtSignal(int)   # addr — main window navigates disasm on double-click

    def __init__(self, session) -> None:
        super().__init__()
        self._session  = session
        self._gadgets: list = []          # full list from last scan
        self._worker   = None
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(200)
        self._filter_timer.timeout.connect(self._apply_filter)
        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── toolbar ──
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"background:{theme.BG_ALT}; border-bottom:1px solid {theme.BORDER};"
        )
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(6, 4, 6, 4)
        tl.setSpacing(6)

        self._status = QLabel("No binary loaded")
        self._status.setStyleSheet(f"color:{theme.FG_DIM}; font-size:11px;")
        tl.addWidget(self._status)
        tl.addStretch()

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("filter gadgets…")
        self._filter_edit.setFixedWidth(220)
        self._filter_edit.setFixedHeight(22)
        self._filter_edit.setStyleSheet(
            f"font-size:11px; background:{theme.BG_SURFACE};"
            f"color:{theme.FG}; border:1px solid {theme.BORDER}; border-radius:3px; padding:0 6px;"
        )
        self._filter_edit.textChanged.connect(lambda _: self._filter_timer.start())
        tl.addWidget(self._filter_edit)

        self._kind_combo = QComboBox()
        self._kind_combo.setFixedHeight(22)
        self._kind_combo.setFixedWidth(70)
        self._kind_combo.setStyleSheet(
            f"font-size:11px; background:{theme.BG_SURFACE};"
            f"color:{theme.FG}; border:1px solid {theme.BORDER}; border-radius:3px;"
        )
        for k in ("ALL", "ROP", "JOP", "SYS"):
            self._kind_combo.addItem(k)
        self._kind_combo.currentTextChanged.connect(lambda _: self._apply_filter())
        tl.addWidget(self._kind_combo)

        self._scan_btn = QPushButton("Scan")
        self._scan_btn.setFixedHeight(22)
        self._scan_btn.setFixedWidth(56)
        self._scan_btn.setStyleSheet(
            f"font-size:11px; padding:0 8px;"
            f"background:{theme.BG_SURFACE}; color:{theme.ACCENT};"
            f"border:1px solid {theme.BORDER}; border-radius:3px; font-weight:600;"
        )
        self._scan_btn.clicked.connect(self.scan)
        tl.addWidget(self._scan_btn)

        layout.addWidget(toolbar)

        # ── table ──
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Address", "Gadget", "Type"])
        self._table.setShowGrid(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setWordWrap(False)

        vh = self._table.verticalHeader()
        assert vh is not None
        vh.setVisible(False)
        vh.setDefaultSectionSize(20)

        hdr = self._table.horizontalHeader()
        assert hdr is not None
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 110)
        self._table.setColumnWidth(2, 48)

        self._table.cellDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

    # ── public ───────────────────────────────────────────────────────────────

    def scan(self) -> None:
        """Start a background gadget scan for the currently loaded binary."""
        from exploit.context import HAS_ROPGADGET
        if not HAS_ROPGADGET:
            self._status.setText("ropgadget not installed")
            return
        if self._session.binary is None:
            self._status.setText("No binary loaded")
            return
        if self._worker and self._worker.isRunning():
            return

        from exploit.gadget_worker import GadgetWorker
        path = self._session.binary.path
        self._status.setText("Scanning…")
        self._scan_btn.setEnabled(False)
        self._gadgets = []
        self._table.setRowCount(0)

        self._worker = GadgetWorker(path, parent=self)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.progress.connect(lambda m: self._status.setText(m))
        self._worker.start()

    # ── internal ─────────────────────────────────────────────────────────────

    def _on_scan_done(self, gadgets: list) -> None:
        self._gadgets = gadgets
        self._scan_btn.setEnabled(True)
        self._apply_filter()

    def _on_scan_error(self, msg: str) -> None:
        self._status.setText(f"Error: {msg}")
        self._scan_btn.setEnabled(True)

    def _apply_filter(self) -> None:
        text  = self._filter_edit.text().lower()
        kind  = self._kind_combo.currentText()
        rows  = [
            g for g in self._gadgets
            if (kind == "ALL" or g["kind"] == kind)
            and (not text or text in g["insns"].lower())
        ]
        self._populate(rows)

    def _populate(self, gadgets: list) -> None:
        font = theme.mono_font(10)
        self._table.setRowCount(len(gadgets))
        for row, g in enumerate(gadgets):
            addr_item = QTableWidgetItem(f"0x{g['addr']:08x}")
            addr_item.setForeground(QColor(theme.COL_ADDR))
            addr_item.setFont(font)
            addr_item.setData(Qt.ItemDataRole.UserRole, g["addr"])

            insn_item = QTableWidgetItem(g["insns"])
            insn_item.setForeground(QColor(theme.FG))
            insn_item.setFont(font)
            insn_item.setData(Qt.ItemDataRole.UserRole, g["addr"])

            kind_item = QTableWidgetItem(g["kind"])
            kind_item.setForeground(QColor(_KIND_COLORS.get(g["kind"], theme.FG_DIM)))
            kind_item.setFont(font)
            kind_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            kind_item.setData(Qt.ItemDataRole.UserRole, g["addr"])

            self._table.setItem(row, 0, addr_item)
            self._table.setItem(row, 1, insn_item)
            self._table.setItem(row, 2, kind_item)

        n = len(gadgets)
        total = len(self._gadgets)
        suffix = f" / {total}" if n != total else ""
        self._status.setText(f"{n}{suffix} gadget{'s' if n != 1 else ''}")

    def _on_double_click(self, row: int, _col: int) -> None:
        item = self._table.item(row, 0)
        if item is None:
            return
        addr = item.data(Qt.ItemDataRole.UserRole)
        if addr is not None:
            self.navigate_to.emit(addr)
