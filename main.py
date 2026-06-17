#!/usr/bin/env python3
"""Huginn Debugger — entry point."""
import sys
import os

# Ensure project root is on the path regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from ui.main_window import MainWindow
from ui.theme import STYLESHEET


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Huginn")
    app.setStyleSheet(STYLESHEET)

    win = MainWindow()

    # If a path was passed on the CLI, open it directly
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        win.session.load(sys.argv[1])
        win._refresh_all()
        b = win.session.binary
        if b:
            win._status_file.setText(
                f"  {b.name}  ·  {b.fmt}  ·  {b.arch}/{b.bits}bit  ·  entry {hex(b.entry_point)}"
            )
            win._status_addr.setText(f"@ {hex(b.entry_point)}")

    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
