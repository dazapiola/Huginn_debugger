"""Dark theme palette and shared style constants."""
from PyQt6.QtGui import QFont

MONO_FONT   = "Fira Code, Cascadia Code, JetBrains Mono, Consolas, Courier New"
MONO_SIZE   = 11

# Colours
BG          = "#1e1e2e"
BG_ALT      = "#181825"
BG_SURFACE  = "#262637"
FG          = "#cdd6f4"
FG_DIM      = "#6c7086"
ACCENT      = "#89b4fa"       # blue
GREEN       = "#a6e3a1"
RED         = "#f38ba8"
YELLOW      = "#f9e2af"
ORANGE      = "#fab387"
MAUVE       = "#cba6f7"
BORDER      = "#313244"

# Instruction group colours
COL_ADDR    = "#89dceb"
COL_BYTES   = "#6c7086"
COL_MNEM    = "#89b4fa"
COL_OPS     = "#cdd6f4"
COL_JUMP    = "#fab387"
COL_CALL    = "#a6e3a1"
COL_RET     = "#f38ba8"
COL_BP      = "#f38ba8"
COL_CURRENT = "#f9e2af"

STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {BG};
    color: {FG};
    font-family: "Segoe UI", "SF Pro Text", "Ubuntu", sans-serif;
    font-size: 13px;
}}
QMenuBar {{
    background-color: {BG_ALT};
    color: {FG};
    border-bottom: 1px solid {BORDER};
}}
QMenuBar::item:selected {{ background-color: {BG_SURFACE}; }}
QMenu {{
    background-color: {BG_ALT};
    color: {FG};
    border: 1px solid {BORDER};
}}
QMenu::item:selected {{ background-color: {ACCENT}; color: {BG}; }}
QToolBar {{
    background-color: {BG_ALT};
    border-bottom: 1px solid {BORDER};
    spacing: 4px;
    padding: 2px 4px;
}}
QToolButton {{
    background: transparent;
    color: {FG};
    border: none;
    padding: 4px 8px;
    border-radius: 4px;
}}
QToolButton:hover  {{ background-color: {BG_SURFACE}; }}
QToolButton:pressed {{ background-color: {BORDER}; }}
QDockWidget {{
    color: {FG};
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}
QDockWidget::title {{
    background-color: {BG_ALT};
    padding: 4px 8px;
    border-bottom: 1px solid {BORDER};
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
QTableView, QTableWidget {{
    background-color: {BG};
    color: {FG};
    gridline-color: {BORDER};
    border: none;
    selection-background-color: {BG_SURFACE};
    selection-color: {FG};
}}
QTableView::item {{ padding: 2px 6px; }}
QHeaderView::section {{
    background-color: {BG_ALT};
    color: {FG_DIM};
    border: none;
    border-right: 1px solid {BORDER};
    padding: 4px 6px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
}}
QScrollBar:vertical {{
    background: {BG_ALT};
    width: 10px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {FG_DIM}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {BG_ALT};
    height: 10px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 5px;
    min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{ background: {FG_DIM}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QStatusBar {{
    background-color: {BG_ALT};
    color: {FG_DIM};
    border-top: 1px solid {BORDER};
    font-size: 12px;
}}
QSplitter::handle {{ background-color: {BORDER}; }}
QLineEdit {{
    background-color: {BG_SURFACE};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 8px;
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QPushButton {{
    background-color: {BG_SURFACE};
    color: {FG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 4px 12px;
}}
QPushButton:hover  {{ background-color: {BORDER}; }}
QPushButton:pressed {{ background-color: {ACCENT}; color: {BG}; }}
QPlainTextEdit {{
    background-color: {BG};
    color: {FG};
    border: none;
    selection-background-color: {BG_SURFACE};
}}
QGraphicsView {{
    background-color: {BG_ALT};
    border: none;
}}
"""


def mono_font(size: int = MONO_SIZE) -> QFont:
    f = QFont()
    for name in MONO_FONT.split(", "):
        f.setFamily(name.strip())
        break
    f.setPointSize(size)
    f.setStyleHint(QFont.StyleHint.Monospace)
    return f
