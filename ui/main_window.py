"""Main window — QMainWindow with dockable panels and a session."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import (
    QMainWindow, QDockWidget, QFileDialog, QLabel,
    QToolBar, QStatusBar, QMessageBox,
)
from PyQt6.QtCore import Qt, QSize, QObject, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence

from core.session import Session
from backends.static_backend import StaticBackend
from ui import theme
from ui.panels.disasm_panel    import DisasmPanel
from ui.panels.hex_panel       import HexPanel
from ui.panels.registers_panel import RegistersPanel
from ui.panels.stack_panel     import StackPanel
from ui.panels.cfg_panel       import CfgPanel


def _check_dynamic_compatible(path: str) -> str | None:
    """Return an error message if the binary can't be spawned with Frida, else None."""
    try:
        import lief
        binary = lief.parse(path)
        if binary is None:
            return None  # let Frida fail with its own error
        fmt = str(binary.format)
        if "ELF" in fmt:
            has_interp = any("INTERP" in str(s.type) for s in binary.segments)
            if not has_interp:
                return (
                    f"'{path}' es un binario ELF estáticamente linkeado.\n\n"
                    "Frida requiere un dynamic linker (PT_INTERP) para inyectar su agente.\n\n"
                    "Compilá el target con gcc para modo dinámico:\n"
                    "  gcc -g -O0 -o target target.c\n\n"
                    "El modo estático (Open binary) sigue disponible para análisis."
                )
        elif "PE" in fmt:
            try:
                imports = list(binary.imports)
                if not imports:
                    return (
                        f"'{path}' es un PE sin imports — posiblemente estático.\n\n"
                        "Frida necesita que el target tenga una tabla de imports (IAT)."
                    )
            except Exception:
                pass
    except Exception:
        pass
    return None


class _StopSignal(QObject):
    """Thread-safe bridge: Frida background thread emits → main thread slot."""
    fired = pyqtSignal()


class _DebugWorker(QThread):
    """Runs a blocking Frida call off the main thread."""
    error = pyqtSignal(str)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            self._fn()
        except Exception as exc:
            self.error.emit(str(exc))


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.session = Session()

        # Wire cross-thread stop signal before setting up the backend
        self._stop_signal = _StopSignal(self)
        self._stop_signal.fired.connect(self._on_process_stopped)
        self.session.on_stopped(lambda _rip: self._stop_signal.fired.emit())

        self.session.setup(StaticBackend())
        self._worker: _DebugWorker | None = None
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

        self.disasm_panel.address_selected.connect(self._on_address_selected)

    def _create_menus(self) -> None:
        mb = self.menuBar()

        # File
        file_menu = mb.addMenu("&File")
        self._act_open = self._action("Open binary…", "Ctrl+O", self.open_file)
        self._act_exit = self._action("Exit",          "Ctrl+Q", self.close)
        file_menu.addAction(self._act_open)
        file_menu.addSeparator()
        file_menu.addAction(self._act_exit)

        # Debug — Run always enabled (asks for file if none loaded)
        debug_menu = mb.addMenu("&Debug")
        self._act_run    = self._action("Run / Spawn",   "F5",  self._do_spawn)
        self._act_step   = self._action("Step",          "F7",  self._do_step,      enabled=False)
        self._act_stepov = self._action("Step Over",     "F8",  self._do_step_over, enabled=False)
        self._act_cont   = self._action("Continue",      "F9",  self._do_continue,  enabled=False)
        self._act_stop   = self._action("Stop",          "F12", self._do_stop,      enabled=False)
        for act in (self._act_run, self._act_step, self._act_stepov,
                    self._act_cont, self._act_stop):
            debug_menu.addAction(act)

        # View
        view_menu = mb.addMenu("&View")
        for title, dock_attr in (
            ("Disassembly", "_dock_disasm"),
            ("Hex Dump",    "_dock_hex"),
            ("Registers",   "_dock_regs"),
            ("Stack",       "_dock_stack"),
            ("CFG",         "_dock_cfg"),
        ):
            act = self._action(title, None, lambda _, a=dock_attr: self._toggle_dock(a))
            act.setCheckable(True)
            act.setChecked(True)
            view_menu.addAction(act)

        # Plugins (stub — mona added in Phase 6)
        self._plugins_menu = mb.addMenu("&Plugins")
        self._plugins_menu.addAction(
            self._action("Mona  (not loaded)", None, self._noop, enabled=False)
        )

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

        self.tabifyDockWidget(self._dock_regs, self._dock_stack)
        self._dock_regs.raise_()

        self.tabifyDockWidget(self._dock_hex, self._dock_cfg)
        self._dock_cfg.raise_()

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

    # ── file actions ──────────────────────────────────────────────────────────

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open binary", "",
            "Executables (*);;ELF (*.elf);;PE (*.exe *.dll)"
        )
        if not path:
            return
        try:
            # Switch back to static backend if we were dynamic
            if not isinstance(self.session.backend, StaticBackend):
                try:
                    self.session.backend.detach()
                except Exception:
                    pass
                self.session.setup(StaticBackend())
                self._reset_to_static()
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

    # ── debug actions ─────────────────────────────────────────────────────────

    def _do_spawn(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        if self.session.binary:
            path = self.session.binary.path
        else:
            path, _ = QFileDialog.getOpenFileName(
                self, "Spawn binary", "", "Executables (*)"
            )
            if not path:
                return
        self._start_dynamic(path)

    def _start_dynamic(self, path: str) -> None:
        err = _check_dynamic_compatible(path)
        if err:
            QMessageBox.warning(self, "Binario no compatible con Frida", err)
            return
        from backends.frida_backend import FridaBackend
        backend = FridaBackend()
        self.session.setup(backend)
        try:
            self.session.load(path)
        except Exception as exc:
            QMessageBox.critical(self, "Error loading binary", str(exc))
            return
        b = self.session.binary
        if b:
            self._status_file.setText(
                f"  {b.name}  ·  {b.fmt}  ·  {b.arch}/{b.bits}bit  ·  entry {hex(b.entry_point)}"
            )
        # Disable all actions while spawning; _on_process_stopped re-enables them
        self._act_run.setEnabled(False)
        self._act_step.setEnabled(False)
        self._act_stepov.setEnabled(False)
        self._act_cont.setEnabled(False)
        self._act_stop.setEnabled(False)
        self._status_mode.setText("dynamic  ·  spawning…")

        worker = _DebugWorker(lambda: backend.spawn(path), self)
        worker.error.connect(self._on_worker_error)
        worker.start()
        self._worker = worker

    def _do_step(self) -> None:
        if not self._is_dynamic():
            return
        self._set_paused(False)
        worker = _DebugWorker(self.session.backend.step, self)
        worker.error.connect(self._on_worker_error)
        worker.start()
        self._worker = worker

    def _do_step_over(self) -> None:
        if not self._is_dynamic():
            return
        self._set_paused(False)
        worker = _DebugWorker(self.session.backend.step_over, self)
        worker.error.connect(self._on_worker_error)
        worker.start()
        self._worker = worker

    def _do_continue(self) -> None:
        if not self._is_dynamic():
            return
        self._set_paused(False)
        try:
            self.session.backend.continue_()
        except Exception as exc:
            QMessageBox.critical(self, "Continue error", str(exc))
            self._set_paused(True)

    def _do_stop(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(2000)
        try:
            self.session.backend.detach()
        except Exception:
            pass
        self.session.setup(StaticBackend())
        self._reset_to_static()
        if self.session.binary:
            self.session.current_address = self.session.binary.entry_point
            self._refresh_all()

    # ── process-stopped handler (main thread, via queued signal) ─────────────

    def _on_process_stopped(self) -> None:
        self._set_paused(True)
        self.disasm_panel.refresh()
        self.registers_panel.refresh()
        self.stack_panel.refresh()
        addr = self.session.current_address or 0
        self._status_addr.setText(f"@ {hex(addr)}")
        pid = getattr(self.session.backend, "_pid", None)
        mode = f"dynamic  ·  PID {pid}" if pid else "dynamic"
        self._status_mode.setText(mode)

    # ── misc event handlers ───────────────────────────────────────────────────

    def _on_address_selected(self, addr: int) -> None:
        self.session.current_address = addr
        self.hex_panel.refresh(addr)
        self._status_addr.setText(f"@ {hex(addr)}")

    def _on_worker_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Debugger error", msg)
        self._set_paused(True)

    def _toggle_dock(self, attr: str) -> None:
        dock: QDockWidget | None = getattr(self, attr, None)
        if dock:
            dock.setVisible(not dock.isVisible())

    def _refresh_all(self) -> None:
        self.disasm_panel.refresh()
        self.hex_panel.refresh()
        self.cfg_panel.refresh()

    # ── state helpers ─────────────────────────────────────────────────────────

    def _set_paused(self, paused: bool) -> None:
        """paused=True → process stopped, step/continue available."""
        self._act_step.setEnabled(paused)
        self._act_stepov.setEnabled(paused)
        self._act_cont.setEnabled(paused)
        self._act_stop.setEnabled(paused)
        self._act_run.setEnabled(not paused)

    def _reset_to_static(self) -> None:
        self._act_step.setEnabled(False)
        self._act_stepov.setEnabled(False)
        self._act_cont.setEnabled(False)
        self._act_stop.setEnabled(False)
        self._act_run.setEnabled(self.session.binary is not None)
        self._status_mode.setText("static")
        self._status_addr.setText("")
        self.registers_panel.refresh()   # clears to "—" (static backend returns {})
        self.stack_panel.clear()

    def _is_dynamic(self) -> bool:
        from backends.frida_backend import FridaBackend
        return isinstance(self.session.backend, FridaBackend)

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
