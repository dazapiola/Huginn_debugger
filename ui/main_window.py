"""Main window — QMainWindow with dockable panels and a session."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import (
    QMainWindow, QDockWidget, QFileDialog, QLabel,
    QToolBar, QStatusBar, QMessageBox,
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QKeySequence

from core.session import Session
from backends.static_backend import StaticBackend
from ui import theme
from ui.panels.disasm_panel   import DisasmPanel
from ui.panels.hex_panel      import HexPanel
from ui.panels.registers_panel import RegistersPanel
from ui.panels.stack_panel    import StackPanel
from ui.panels.cfg_panel      import CfgPanel


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.session = Session()
        self.session.setup(StaticBackend())
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("Huginn Debugger")
        self.resize(1400, 900)
        self.setDockOptions(
            QMainWindow.DockOption.AllowTabbedDocks |
            QMainWindow.DockOption.AnimatedDocks
        )

        self._create_panels()
        self._create_menus()
        self._create_toolbar()
        self._create_statusbar()
        self._arrange_docks()

    def _create_panels(self) -> None:
        self.disasm_panel    = DisasmPanel(self.session)
        self.hex_panel       = HexPanel(self.session)
        self.registers_panel = RegistersPanel(self.session)
        self.stack_panel     = StackPanel(self.session)
        self.cfg_panel       = CfgPanel(self.session)

        # Wire disasm → hex sync on address click
        self.disasm_panel.address_selected.connect(self._on_address_selected)

    def _create_menus(self) -> None:
        mb = self.menuBar()

        # File
        file_menu = mb.addMenu("&File")
        self._act_open   = self._action("Open binary…", "Ctrl+O", self.open_file)
        self._act_exit   = self._action("Exit",          "Ctrl+Q", self.close)
        file_menu.addAction(self._act_open)
        file_menu.addSeparator()
        file_menu.addAction(self._act_exit)

        # Debug
        debug_menu = mb.addMenu("&Debug")
        self._act_run    = self._action("Run / Spawn",   "F5",    self._noop, enabled=False)
        self._act_step   = self._action("Step",          "F7",    self._noop, enabled=False)
        self._act_stepov = self._action("Step Over",     "F8",    self._noop, enabled=False)
        self._act_cont   = self._action("Continue",      "F9",    self._noop, enabled=False)
        self._act_stop   = self._action("Stop",          "F12",   self._noop, enabled=False)
        for act in (self._act_run, self._act_step, self._act_stepov,
                    self._act_cont, self._act_stop):
            debug_menu.addAction(act)

        # View
        view_menu = mb.addMenu("&View")
        for title, dock_attr in (
            ("Disassembly",  "_dock_disasm"),
            ("Hex Dump",     "_dock_hex"),
            ("Registers",    "_dock_regs"),
            ("Stack",        "_dock_stack"),
            ("CFG",          "_dock_cfg"),
        ):
            act = self._action(title, None, lambda _, a=dock_attr: self._toggle_dock(a))
            act.setCheckable(True)
            act.setChecked(True)
            view_menu.addAction(act)

        # Plugins (stub — mona added in Phase 6)
        self._plugins_menu = mb.addMenu("&Plugins")
        self._plugins_menu.addAction(self._action("Mona  (not loaded)", None, self._noop, enabled=False))

    def _create_toolbar(self) -> None:
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))

        tb.addAction(self._act_open)
        tb.addSeparator()
        tb.addAction(self._act_run)
        tb.addAction(self._act_step)
        tb.addAction(self._act_stepov)
        tb.addAction(self._act_cont)
        tb.addAction(self._act_stop)

    def _create_statusbar(self) -> None:
        sb = QStatusBar()
        self._status_mode = QLabel("static")
        self._status_mode.setStyleSheet(
            f"color: {theme.ACCENT}; font-weight: 600; padding: 0 8px;"
        )
        self._status_file = QLabel("No binary loaded")
        self._status_addr = QLabel("")
        self._status_addr.setStyleSheet(f"color: {theme.FG_DIM}; padding: 0 8px;")

        sb.addPermanentWidget(self._status_mode)
        sb.addWidget(self._status_file)
        sb.addPermanentWidget(self._status_addr)
        self.setStatusBar(sb)

    def _arrange_docks(self) -> None:
        def dock(title: str, widget, area: Qt.DockWidgetArea) -> QDockWidget:
            d = QDockWidget(title, self)
            d.setObjectName(title.replace(" ", "_"))
            d.setWidget(widget)
            d.setFeatures(
                QDockWidget.DockWidgetFeature.DockWidgetMovable |
                QDockWidget.DockWidgetFeature.DockWidgetFloatable |
                QDockWidget.DockWidgetFeature.DockWidgetClosable
            )
            self.addDockWidget(area, d)
            return d

        L = Qt.DockWidgetArea.LeftDockWidgetArea
        R = Qt.DockWidgetArea.RightDockWidgetArea
        B = Qt.DockWidgetArea.BottomDockWidgetArea

        self._dock_disasm = dock("Disassembly", self.disasm_panel,    L)
        self._dock_regs   = dock("Registers",   self.registers_panel, R)
        self._dock_stack  = dock("Stack",        self.stack_panel,     R)
        self._dock_hex    = dock("Hex Dump",     self.hex_panel,       B)
        self._dock_cfg    = dock("CFG",          self.cfg_panel,       B)

        # Tab Registers + Stack together on the right
        self.tabifyDockWidget(self._dock_regs, self._dock_stack)
        self._dock_regs.raise_()

        # Tab Hex + CFG together on the bottom
        self.tabifyDockWidget(self._dock_hex, self._dock_cfg)
        self._dock_cfg.raise_()

        # Resize: disasm gets more vertical space
        self.resizeDocks(
            [self._dock_disasm, self._dock_regs],
            [900, 480],
            Qt.Orientation.Horizontal,
        )
        self.resizeDocks(
            [self._dock_disasm, self._dock_cfg],
            [540, 340],
            Qt.Orientation.Vertical,
        )

    # ── actions ───────────────────────────────────────────────────────────────

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open binary", "",
            "Executables (*);;ELF (*.elf);;PE (*.exe *.dll)"
        )
        if not path:
            return
        try:
            self.session.load(path)
            self._refresh_all()
            b = self.session.binary
            assert b is not None
            self._status_file.setText(
                f"  {b.name}  ·  {b.fmt}  ·  {b.arch}/{b.bits}bit  ·  entry {hex(b.entry_point)}"
            )
            self._status_addr.setText(f"@ {hex(b.entry_point)}")
        except Exception as exc:
            QMessageBox.critical(self, "Error loading binary", str(exc))

    def _on_address_selected(self, addr: int) -> None:
        self.session.current_address = addr
        self.hex_panel.refresh(addr)
        self._status_addr.setText(f"@ {hex(addr)}")

    def _toggle_dock(self, attr: str) -> None:
        dock: QDockWidget | None = getattr(self, attr, None)
        if dock:
            dock.setVisible(not dock.isVisible())

    def _refresh_all(self) -> None:
        self.disasm_panel.refresh()
        self.hex_panel.refresh()
        self.cfg_panel.refresh()
        # Registers and stack stay empty in static mode

    def _noop(self) -> None:
        pass

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _action(
        label: str,
        shortcut: str | None,
        slot,
        enabled: bool = True,
    ) -> QAction:
        act = QAction(label)
        if shortcut:
            act.setShortcut(QKeySequence(shortcut))
        act.triggered.connect(slot)
        act.setEnabled(enabled)
        return act
