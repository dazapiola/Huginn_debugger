"""About dialog — logo, version, authors."""
from __future__ import annotations
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QFont

from ui import theme

_LOGO = os.path.join(os.path.dirname(__file__), "..", "logo", "cuervo_huginn.png")

_VERSION = "1.0.0"
_AUTHOR  = "Alejandro Zapiola"
_COAUTHOR = "Claude (Anthropic)"


class AboutDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Acerca de Huginn")
        self.setFixedSize(520, 440)
        self.setStyleSheet(f"""
            QDialog {{
                background: {theme.BG};
                color: {theme.FG};
            }}
            QLabel {{
                background: transparent;
                color: {theme.FG};
            }}
        """)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(0)

        # ── logo ──
        logo_label = QLabel()
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        px = QPixmap(_LOGO)
        if not px.isNull():
            px = px.scaledToWidth(460, Qt.TransformationMode.SmoothTransformation)
        logo_label.setPixmap(px)
        layout.addWidget(logo_label)

        layout.addSpacing(20)

        # ── version ──
        ver = QLabel(f"Versión {_VERSION}")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver.setStyleSheet(f"color:{theme.FG_DIM}; font-size:13px; letter-spacing:1px;")
        layout.addWidget(ver)

        layout.addSpacing(20)

        # ── separator ──
        sep = QLabel()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{theme.BORDER};")
        layout.addWidget(sep)

        layout.addSpacing(16)

        # ── authors ──
        author_font = QFont()
        author_font.setPointSize(11)

        author_lbl = QLabel(f"Autor:  <b>{_AUTHOR}</b>")
        author_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        author_lbl.setFont(author_font)
        author_lbl.setStyleSheet(f"color:{theme.FG};")
        layout.addWidget(author_lbl)

        layout.addSpacing(6)

        co_lbl = QLabel(f"Co-autor:  <b>{_COAUTHOR}</b>")
        co_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        co_lbl.setFont(author_font)
        co_lbl.setStyleSheet(f"color:{theme.FG_DIM};")
        layout.addWidget(co_lbl)

        layout.addSpacing(20)

        # ── close button ──
        btn = QPushButton("Cerrar")
        btn.setFixedWidth(100)
        btn.setStyleSheet(f"""
            QPushButton {{
                background:{theme.BG_SURFACE}; color:{theme.FG};
                border:1px solid {theme.BORDER}; border-radius:4px; padding:5px 0;
            }}
            QPushButton:hover {{ background:{theme.ACCENT}; color:{theme.BG}; }}
        """)
        btn.clicked.connect(self.accept)

        btn_row = QVBoxLayout()
        btn_row.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(btn_row)
