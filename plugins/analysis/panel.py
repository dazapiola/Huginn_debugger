"""Analysis panel — shows detected functions and loops, double-click to navigate."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from PyQt6.QtWidgets import (
    QDockWidget, QWidget, QVBoxLayout, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from ui import theme


class AnalysisPanel(QDockWidget):
    navigate_to = pyqtSignal(int)   # emitted on double-click — address to go to

    def __init__(self, session, parent=None) -> None:
        super().__init__("Analysis", parent)
        self._session = session
        self._analyzed_path: str | None = None
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
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            f"QTabBar::tab {{ background:{theme.BG_ALT}; color:{theme.FG_DIM};"
            f" padding:4px 12px; border:none; }}"
            f"QTabBar::tab:selected {{ color:{theme.FG}; border-bottom:2px solid {theme.ACCENT}; }}"
        )
        layout.addWidget(self._tabs)

        self._fn_table  = self._make_table(["Address", "Name"])
        self._loop_table = self._make_table(["Address", "Info"])

        self._tabs.addTab(self._fn_table,   "Functions")
        self._tabs.addTab(self._loop_table, "Loops")

        self._fn_table.cellDoubleClicked.connect(
            lambda r, _c: self._emit_navigate(self._fn_table, r)
        )
        self._loop_table.cellDoubleClicked.connect(
            lambda r, _c: self._emit_navigate(self._loop_table, r)
        )

    def _make_table(self, headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        t.setShowGrid(False)
        t.setFont(theme.mono_font())

        vh = t.verticalHeader()
        assert vh is not None
        vh.setVisible(False)
        vh.setDefaultSectionSize(20)

        hdr = t.horizontalHeader()
        assert hdr is not None
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        t.setColumnWidth(0, 120)
        return t

    # ── public API ────────────────────────────────────────────────────────────

    def analyze(self) -> None:
        """Run analysis on current binary (skips if already analyzed this binary)."""
        b = self._session.binary
        if b is None:
            return
        if b.path == self._analyzed_path:
            return
        self._analyzed_path = b.path

        from plugins.analysis.engine import run
        run(self._session)
        self._populate()

    def refresh_view(self) -> None:
        """Re-populate tables from session data without re-running analysis."""
        self._populate()

    # ── internals ─────────────────────────────────────────────────────────────

    def _populate(self) -> None:
        self._fill_functions()
        self._fill_loops()

    def _fill_functions(self) -> None:
        labels = self._session.labels
        self._fn_table.setRowCount(0)
        font = theme.mono_font()
        # Sort by address
        for addr, name in sorted(labels.items()):
            row = self._fn_table.rowCount()
            self._fn_table.insertRow(row)

            addr_item = QTableWidgetItem(f"0x{addr:016x}")
            addr_item.setForeground(QColor(theme.COL_ADDR))
            addr_item.setFont(font)
            addr_item.setData(Qt.ItemDataRole.UserRole, addr)

            name_item = QTableWidgetItem(name)
            name_item.setForeground(QColor(theme.GREEN))
            name_item.setFont(font)

            self._fn_table.setItem(row, 0, addr_item)
            self._fn_table.setItem(row, 1, name_item)

    def _fill_loops(self) -> None:
        headers = self._session.loop_headers
        self._loop_table.setRowCount(0)
        font = theme.mono_font()
        for addr in sorted(headers):
            row = self._loop_table.rowCount()
            self._loop_table.insertRow(row)

            addr_item = QTableWidgetItem(f"0x{addr:016x}")
            addr_item.setForeground(QColor(theme.COL_ADDR))
            addr_item.setFont(font)
            addr_item.setData(Qt.ItemDataRole.UserRole, addr)

            # Check if this loop header is also a known function
            label = self._session.labels.get(addr, "")
            info = f"↩ loop header" + (f"  ({label})" if label else "")
            info_item = QTableWidgetItem(info)
            info_item.setForeground(QColor(theme.MAUVE))
            info_item.setFont(font)

            self._loop_table.setItem(row, 0, addr_item)
            self._loop_table.setItem(row, 1, info_item)

    def _emit_navigate(self, table: QTableWidget, row: int) -> None:
        item = table.item(row, 0)
        if item:
            addr = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(addr, int):
                self.navigate_to.emit(addr)
