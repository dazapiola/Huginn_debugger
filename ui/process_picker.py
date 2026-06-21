"""Dialog for selecting a running process to attach to."""
from __future__ import annotations
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QPushButton, QLabel, QAbstractItemView,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor

from ui import theme

_COLS = ["PID", "Name", "Command"]


def _read_processes() -> list[tuple[int, str, str]]:
    """Return (pid, name, cmdline) for every readable process in /proc."""
    rows: list[tuple[int, str, str]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
        except OSError:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            cmdline = name
        rows.append((pid, name, cmdline))
    rows.sort(key=lambda r: r[0])
    return rows


class ProcessPickerDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Attach to Process")
        self.setMinimumSize(720, 480)
        self.resize(800, 520)
        self._all_rows: list[tuple[int, str, str]] = []
        self._selected_pid: int | None = None
        self._build_ui()
        self._load()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        self.setStyleSheet(f"""
            QDialog {{ background:{theme.BG}; color:{theme.FG}; }}
            QLabel  {{ color:{theme.FG}; }}
            QLineEdit {{
                background:{theme.BG_SURFACE}; color:{theme.FG};
                border:1px solid {theme.BORDER}; border-radius:4px; padding:4px 8px;
            }}
            QTableWidget {{
                background:{theme.BG}; color:{theme.FG};
                gridline-color:{theme.BORDER}; border:1px solid {theme.BORDER};
                selection-background-color:{theme.BG_SURFACE};
            }}
            QHeaderView::section {{
                background:{theme.BG_ALT}; color:{theme.FG_DIM};
                border:none; border-bottom:1px solid {theme.BORDER}; padding:4px;
            }}
            QPushButton {{
                background:{theme.BG_SURFACE}; color:{theme.FG};
                border:1px solid {theme.BORDER}; border-radius:4px;
                padding:5px 16px;
            }}
            QPushButton:hover  {{ background:{theme.ACCENT}; color:{theme.BG}; }}
            QPushButton:default {{ border-color:{theme.ACCENT}; }}
        """)

        # ── search bar ──
        top = QHBoxLayout()
        top.addWidget(QLabel("Filter:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Buscar por nombre o comando…")
        self._search.textChanged.connect(self._on_filter)
        top.addWidget(self._search)

        self._count_label = QLabel("0 procesos")
        self._count_label.setStyleSheet(f"color:{theme.FG_DIM}; font-size:11px;")
        top.addWidget(self._count_label)

        btn_refresh = QPushButton("↺  Refresh")
        btn_refresh.setFixedWidth(100)
        btn_refresh.clicked.connect(self._load)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        # ── table ──
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(_COLS)
        self._table.setShowGrid(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            self._table.styleSheet() +
            f"QTableWidget {{ alternate-background-color:{theme.BG_ALT}; }}"
        )

        vh = self._table.verticalHeader()
        assert vh is not None
        vh.setVisible(False)
        vh.setDefaultSectionSize(22)

        hdr = self._table.horizontalHeader()
        assert hdr is not None
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(0, 72)
        self._table.setColumnWidth(1, 180)

        self._table.cellDoubleClicked.connect(self._accept)
        self._table.itemSelectionChanged.connect(self._on_selection)
        layout.addWidget(self._table)

        # ── buttons ──
        bottom = QHBoxLayout()
        bottom.addStretch()
        btn_cancel = QPushButton("Cancelar")
        btn_cancel.clicked.connect(self.reject)
        self._btn_attach = QPushButton("Attach")
        self._btn_attach.setDefault(True)
        self._btn_attach.setEnabled(False)
        self._btn_attach.clicked.connect(self._accept)
        bottom.addWidget(btn_cancel)
        bottom.addWidget(self._btn_attach)
        layout.addLayout(bottom)

    # ── data ──────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        self._all_rows = _read_processes()
        self._populate(self._filter_rows(self._search.text()))

    def _filter_rows(self, text: str) -> list[tuple[int, str, str]]:
        q = text.strip().lower()
        if not q:
            return self._all_rows
        return [r for r in self._all_rows if q in r[1].lower() or q in r[2].lower()]

    def _on_filter(self, text: str) -> None:
        self._populate(self._filter_rows(text))

    def _populate(self, rows: list[tuple[int, str, str]]) -> None:
        font = QFont(theme.MONO_FONT, theme.MONO_SIZE - 1)
        self._table.setRowCount(len(rows))
        for row, (pid, name, cmdline) in enumerate(rows):
            pid_item = QTableWidgetItem(str(pid))
            pid_item.setFont(font)
            pid_item.setForeground(QColor(theme.COL_ADDR))
            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            pid_item.setData(Qt.ItemDataRole.UserRole, pid)

            name_item = QTableWidgetItem(name)
            name_item.setFont(font)
            name_item.setForeground(QColor(theme.GREEN))

            cmd_item = QTableWidgetItem(cmdline)
            cmd_item.setFont(font)
            cmd_item.setForeground(QColor(theme.FG_DIM))

            self._table.setItem(row, 0, pid_item)
            self._table.setItem(row, 1, name_item)
            self._table.setItem(row, 2, cmd_item)

        n = len(rows)
        self._count_label.setText(f"{n} proceso{'s' if n != 1 else ''}")
        self._btn_attach.setEnabled(False)

    # ── interaction ───────────────────────────────────────────────────────────

    def _on_selection(self) -> None:
        self._btn_attach.setEnabled(self._table.currentRow() >= 0)

    def _accept(self, *_) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if item is None:
            return
        self._selected_pid = item.data(Qt.ItemDataRole.UserRole)
        self.accept()

    def selected_pid(self) -> int | None:
        return self._selected_pid
