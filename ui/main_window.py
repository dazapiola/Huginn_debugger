"""Main window — QMainWindow with dockable panels and a session."""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PyQt6.QtWidgets import (
    QDialog, QMainWindow, QDockWidget, QFileDialog, QInputDialog,
    QLabel, QStatusBar, QMessageBox,
)
from PyQt6.QtCore import Qt, QSize, QObject, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence

from core.session import Session
from backends.static_backend import StaticBackend
from ui import theme
from ui.panels.disasm_panel       import DisasmPanel
from ui.panels.hex_panel          import HexPanel
from ui.panels.registers_panel    import RegistersPanel
from ui.panels.stack_panel        import StackPanel
from ui.panels.cfg_panel          import CfgPanel
from ui.panels.breakpoints_panel  import BreakpointsPanel
from ui.panels.log_panel          import LogPanel
from ui.panels.rop_panel          import ROPPanel
from ui.panels.exploit_console    import ExploitConsolePanel
from ui.panels.shellcraft_panel   import ShellcraftPanel


class _StopSignal(QObject):
    """Thread-safe bridge: GDB reader thread emits → main thread slot."""
    fired = pyqtSignal()


class _DebugWorker(QThread):
    """Runs a blocking GDB call off the main thread."""
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
        self.disasm_panel       = DisasmPanel(self.session)
        self.hex_panel          = HexPanel(self.session)
        self.registers_panel    = RegistersPanel(self.session)
        self.stack_panel        = StackPanel(self.session)
        self.cfg_panel          = CfgPanel(self.session)
        self.breakpoints_panel  = BreakpointsPanel(self.session)
        self.log_panel          = LogPanel(self.session)
        self.rop_panel          = ROPPanel(self.session)
        self.exploit_console    = ExploitConsolePanel(self.session)
        self.shellcraft_panel   = ShellcraftPanel(self.session)

        self.disasm_panel.address_selected.connect(self._on_address_selected)
        self.breakpoints_panel.navigate_to.connect(self._on_analysis_navigate)
        self.rop_panel.navigate_to.connect(self._on_analysis_navigate)
        self.shellcraft_panel.shellcode_ready.connect(
            lambda shellcode, name: (
                self.exploit_console.inject_shellcode(shellcode, name),
                self._dock_exploit.raise_(),
            )
        )

        self._plugin_panels: list = []
        try:
            from plugins import load_all
            self._plugin_panels = load_all(self.session)
            for panel in self._plugin_panels:
                if hasattr(panel, "navigate_to"):
                    panel.navigate_to.connect(self._on_analysis_navigate)
        except Exception as exc:
            print(f"[main] plugins load failed: {exc}")

    def _create_menus(self) -> None:
        mb = self.menuBar()

        # ── File ──────────────────────────────────────────────────────────────
        file_menu = mb.addMenu("&File")
        self._act_open   = self._action("Open binary…",         "Ctrl+O", self.open_file)
        self._act_attach = self._action("Attach to process…",   "Ctrl+P", self._do_attach)
        self._act_export = self._action("Export disassembly…",  "Ctrl+E", self._do_export,
                                        enabled=False)
        self._act_exit   = self._action("Exit",                 "Ctrl+Q", self.close)
        file_menu.addAction(self._act_open)
        file_menu.addAction(self._act_attach)
        file_menu.addSeparator()
        file_menu.addAction(self._act_export)
        file_menu.addSeparator()
        file_menu.addAction(self._act_exit)

        # ── Debug ─────────────────────────────────────────────────────────────
        debug_menu = mb.addMenu("&Debug")
        self._act_run      = self._action("Run / Spawn",       "F5",     self._do_spawn)
        self._act_restart  = self._action("Restart",           "Ctrl+R", self._do_restart,   enabled=False)
        self._act_step     = self._action("Step",              "F7",     self._do_step,      enabled=False)
        self._act_stepov   = self._action("Step Over",         "F8",     self._do_step_over, enabled=False)
        self._act_cont     = self._action("Continue",          "F9",     self._do_continue,  enabled=False)
        self._act_stop     = self._action("Stop",              "F12",    self._do_stop,      enabled=False)
        debug_menu.addAction(self._act_run)
        debug_menu.addAction(self._act_restart)
        debug_menu.addSeparator()
        debug_menu.addAction(self._act_step)
        debug_menu.addAction(self._act_stepov)
        debug_menu.addAction(self._act_cont)
        debug_menu.addAction(self._act_stop)
        debug_menu.addSeparator()
        self._act_toggle_bp = self._action("Toggle Breakpoint", "F2",    self._do_toggle_bp, enabled=False)
        self._act_goto      = self._action("Go to Address…",   "Ctrl+G", self._do_goto,      enabled=False)
        debug_menu.addAction(self._act_toggle_bp)
        debug_menu.addAction(self._act_goto)

        # ── View ──────────────────────────────────────────────────────────────
        view_menu = mb.addMenu("&View")
        for title, dock_attr in (
            ("Disassembly",    "_dock_disasm"),
            ("Hex Dump",       "_dock_hex"),
            ("Registers",      "_dock_regs"),
            ("Stack",          "_dock_stack"),
            ("CFG",            "_dock_cfg"),
            ("Breakpoints",    "_dock_bps"),
            ("Log",            "_dock_log"),
            ("ROP Gadgets",    "_dock_rop"),
            ("Exploit Console","_dock_exploit"),
            ("Shellcraft",     "_dock_shellcraft"),
        ):
            act = self._action(title, None, lambda _, a=dock_attr: self._toggle_dock(a))
            act.setCheckable(True)
            act.setChecked(True)
            view_menu.addAction(act)

        # ── Plugins ───────────────────────────────────────────────────────────
        self._plugins_menu = mb.addMenu("&Plugins")
        if self._plugin_panels:
            for panel in self._plugin_panels:
                act = self._action(
                    panel.windowTitle(), None,
                    lambda _, p=panel: p.setVisible(not p.isVisible()),
                )
                act.setCheckable(True)
                act.setChecked(True)
                self._plugins_menu.addAction(act)
        else:
            self._plugins_menu.addAction(
                self._action("No plugins loaded", None, self._noop, enabled=False)
            )

        # ── Ayuda ─────────────────────────────────────────────────────────────
        help_menu = mb.addMenu("A&yuda")
        self._act_about = self._action("Acerca de Huginn…", None, self._do_about)
        help_menu.addAction(self._act_about)

    def _do_about(self) -> None:
        from ui.about_dialog import AboutDialog
        AboutDialog(self).exec()

    def _create_toolbar(self) -> None:
        tb = self.addToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(16, 16))

        tb.addAction(self._act_open)
        tb.addAction(self._act_attach)
        tb.addSeparator()
        tb.addAction(self._act_run)
        tb.addAction(self._act_restart)
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

        self._dock_disasm = dock("Disassembly", self.disasm_panel,       L)
        self._dock_regs   = dock("Registers",   self.registers_panel,   R)
        self._dock_stack  = dock("Stack",        self.stack_panel,       R)
        self._dock_bps    = dock("Breakpoints",  self.breakpoints_panel, R)
        self._dock_hex    = dock("Hex Dump",     self.hex_panel,         B)
        self._dock_cfg    = dock("CFG",          self.cfg_panel,         B)
        self._dock_log    = dock("Log",          self.log_panel,         B)
        self._dock_rop     = dock("ROP Gadgets",   self.rop_panel,       B)
        self._dock_exploit    = dock("Exploit Console", self.exploit_console,  B)
        self._dock_shellcraft = dock("Shellcraft",      self.shellcraft_panel, B)

        self.tabifyDockWidget(self._dock_regs, self._dock_stack)
        self.tabifyDockWidget(self._dock_stack, self._dock_bps)
        self._dock_regs.raise_()
        self.tabifyDockWidget(self._dock_hex, self._dock_cfg)
        self.tabifyDockWidget(self._dock_cfg, self._dock_log)
        self.tabifyDockWidget(self._dock_log, self._dock_rop)
        self.tabifyDockWidget(self._dock_rop, self._dock_exploit)
        self.tabifyDockWidget(self._dock_exploit, self._dock_shellcraft)

        # Add plugin panels to bottom area, tabbed with hex/cfg
        for panel in self._plugin_panels:
            panel.setObjectName(panel.windowTitle().replace(" ", "_") + "_dock")
            self.addDockWidget(B, panel)
            self.tabifyDockWidget(self._dock_hex, panel)

        self._dock_cfg.raise_()

        self.resizeDocks(
            [self._dock_disasm, self._dock_regs], [900, 480], Qt.Orientation.Horizontal,
        )
        self.resizeDocks(
            [self._dock_disasm, self._dock_cfg], [540, 340], Qt.Orientation.Vertical,
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
            self._act_export.setEnabled(True)
            self._act_toggle_bp.setEnabled(True)
            self._act_goto.setEnabled(True)
            self._act_restart.setEnabled(True)
        except Exception as exc:
            QMessageBox.critical(self, "Error loading binary", str(exc))

    def _do_export(self) -> None:
        if self.session.binary is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export disassembly", f"{self.session.binary.name}.asm",
            "Text files (*.asm *.txt);;All files (*)"
        )
        if not path:
            return
        try:
            rows = self.disasm_panel._model._rows
            lines = [
                f"; Disassembly of {self.session.binary.name}",
                f"; Entry point: {hex(self.session.binary.entry_point)}",
                "",
            ]
            for insn in rows:
                comment = f"  → 0x{insn.jump_target:x}" if insn.jump_target else ""
                lines.append(
                    f"0x{insn.address:08x}  {insn.hex_bytes:<24}  {insn.mnemonic} {insn.op_str}{comment}"
                )
            with open(path, "w") as f:
                f.write("\n".join(lines))
            self.statusBar().showMessage(f"Exported {len(rows)} instructions to {path}", 4000)
        except Exception as exc:
            QMessageBox.critical(self, "Export error", str(exc))

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

    def _do_attach(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        from ui.process_picker import ProcessPickerDialog
        dlg = ProcessPickerDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        pid = dlg.selected_pid()
        if pid is None:
            return
        self._start_attach(pid)

    def _start_dynamic(self, path: str) -> None:
        from backends.gdb_backend import GDBBackend
        backend = GDBBackend()
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
        self._disable_all_debug_actions()
        self._act_restart.setEnabled(True)
        self._status_mode.setText("dynamic  ·  spawning…")

        pending_bps = set(self.session.breakpoints)

        def _do_spawn_work():
            backend.spawn(path)
            for addr in pending_bps:
                try:
                    backend.set_breakpoint(addr)
                except Exception:
                    pass

        worker = _DebugWorker(_do_spawn_work, self)
        worker.error.connect(self._on_worker_error)
        worker.finished.connect(lambda: self._on_spawn_running(backend))
        worker.start()
        self._worker = worker

    def _on_spawn_running(self, backend) -> None:
        # GDB spawn() blocks until the entry stop, so _on_process_stopped may have
        # already run by the time this fires.  Don't override the paused state.
        if self._act_step.isEnabled():
            return
        pid = getattr(backend, "_pid", None)
        self._act_stop.setEnabled(True)
        self._act_restart.setEnabled(True)
        pid_str = f"  ·  PID {pid}" if pid else ""
        self._status_mode.setText(f"dynamic{pid_str}  ·  running")

    def _start_attach(self, pid: int) -> None:
        from backends.gdb_backend import GDBBackend

        # Try to auto-detect the binary path from /proc.
        exe_path: str | None = None
        try:
            raw = os.readlink(f"/proc/{pid}/exe")
            exe_path = raw.removesuffix(" (deleted)") if raw else None
        except FileNotFoundError:
            QMessageBox.critical(self, "Attach error", f"No existe el proceso con PID {pid}.")
            return
        except PermissionError:
            # Huginn no tiene permisos para leer /proc/PID/exe (necesitaría root).
            # Ofrecemos selección manual del binario.
            ans = QMessageBox.question(
                self, "Permiso denegado",
                f"/proc/{pid}/exe: permiso denegado.\n\n"
                "¿Querés seleccionar el binario manualmente?\n"
                "(Si no, se attachea sin símbolos — funcionalidad reducida.)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
            )
            if ans == QMessageBox.StandardButton.Cancel:
                return
            if ans == QMessageBox.StandardButton.Yes:
                exe_path, _ = QFileDialog.getOpenFileName(
                    self, "Seleccionar binario del proceso", "", "Executables (*)"
                )
                if not exe_path:
                    return
            # else: exe_path stays None → attach blind
        except OSError as exc:
            QMessageBox.critical(self, "Attach error", f"/proc/{pid}/exe: {exc}")
            return

        backend = GDBBackend()
        self.session.setup(backend)

        if exe_path:
            try:
                self.session.load(exe_path)
            except Exception as exc:
                QMessageBox.critical(self, "Error cargando binario", str(exc))
                return
            b = self.session.binary
            if b:
                self._status_file.setText(
                    f"  {b.name}  ·  {b.fmt}  ·  {b.arch}/{b.bits}bit  ·  entry {hex(b.entry_point)}"
                )
            self._refresh_all()
        else:
            self._status_file.setText(f"  PID {pid}  ·  (sin binario)")

        self._disable_all_debug_actions()
        self._act_stop.setEnabled(True)
        self._status_mode.setText(f"dynamic  ·  attaching to PID {pid}…")

        pending_bps = set(self.session.breakpoints)

        def _do_attach_work() -> None:
            backend.attach(pid)
            for addr in pending_bps:
                try:
                    backend.set_breakpoint(addr)
                except Exception:
                    pass

        worker = _DebugWorker(_do_attach_work, self)
        worker.error.connect(self._on_worker_error)
        worker.finished.connect(lambda: self._on_attach_done(backend, pid))
        worker.start()
        self._worker = worker

    def _on_attach_done(self, backend, pid: int) -> None:
        # _on_process_stopped fires first (from _stop_callback) if *stopped arrived.
        # This callback updates the status label; the guard avoids double-pausing.
        if self._act_step.isEnabled():
            return
        self._act_stop.setEnabled(True)
        self._status_mode.setText(f"dynamic  ·  PID {pid}  ·  attached")

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
        worker = _DebugWorker(self.session.backend.continue_, self)
        worker.error.connect(self._on_worker_error)
        worker.start()
        self._worker = worker

    def _do_stop(self) -> None:
        path = self.session.binary.path if self.session.binary else None
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(2000)
        try:
            self.session.backend.detach()
        except Exception:
            pass
        self.session.setup(StaticBackend())
        self._reset_to_static()
        if path:
            try:
                self.session.load(path)
                self._refresh_all()
            except Exception:
                pass

    def _do_restart(self) -> None:
        path = self.session.binary.path if self.session.binary else None
        if not path:
            return
        was_dynamic = self._is_dynamic()
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(2000)
        try:
            self.session.backend.detach()
        except Exception:
            pass
        if was_dynamic:
            self._start_dynamic(path)
        else:
            self.session.setup(StaticBackend())
            self._reset_to_static()
            try:
                self.session.load(path)
                self._refresh_all()
                b = self.session.binary
                if b:
                    self._status_file.setText(
                        f"  {b.name}  ·  {b.fmt}  ·  {b.arch}/{b.bits}bit  ·  entry {hex(b.entry_point)}"
                    )
                    self._status_addr.setText(f"@ {hex(b.entry_point)}")
                    self._act_restart.setEnabled(True)
            except Exception as exc:
                QMessageBox.critical(self, "Error reloading binary", str(exc))

    def _do_toggle_bp(self) -> None:
        addr = self.session.current_address
        if addr is None:
            return
        model = self.disasm_panel._model
        row = model.row_for_address(addr)
        if row >= 0:
            model.toggle_breakpoint(row)
        else:
            # Address not in current view — toggle directly on session + backend
            if addr in self.session.breakpoints:
                self.session.breakpoints.discard(addr)
                try:
                    self.session.backend.remove_breakpoint(addr)
                except Exception:
                    pass
            else:
                self.session.breakpoints.add(addr)
                try:
                    self.session.backend.set_breakpoint(addr)
                except Exception:
                    pass
            self.session.notify_breakpoints_changed()

    def _do_goto(self) -> None:
        if self.session.binary is None:
            return
        current_hex = hex(self.session.current_address) if self.session.current_address else "0x0"
        addr_str, ok = QInputDialog.getText(
            self, "Go to address", "Address (hex):", text=current_hex
        )
        if not ok or not addr_str.strip():
            return
        try:
            addr = int(addr_str.strip(), 16)
        except ValueError:
            QMessageBox.warning(self, "Dirección inválida", f"'{addr_str}' no es una dirección hex válida.")
            return
        self.session.current_address = addr
        self.disasm_panel.refresh(addr)
        self._status_addr.setText(f"@ {hex(addr)}")

    # ── process-stopped handler (main thread, via queued signal) ─────────────

    def _on_process_stopped(self) -> None:
        self._set_paused(True)
        self.disasm_panel.refresh()
        self.registers_panel.refresh()
        self.stack_panel.refresh()
        self.breakpoints_panel.refresh()
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

    def _on_analysis_navigate(self, addr: int) -> None:
        self.session.current_address = addr
        self.disasm_panel.refresh(addr)
        self.hex_panel.refresh(addr)
        self._status_addr.setText(f"@ {hex(addr)}")

    def _on_worker_error(self, msg: str) -> None:
        self.session.emit_log(f"Error: {msg}", "err")
        QMessageBox.critical(self, "Debugger error", msg)
        self._set_paused(True)

    def _toggle_dock(self, attr: str) -> None:
        dock: QDockWidget | None = getattr(self, attr, None)
        if dock:
            dock.setVisible(not dock.isVisible())

    def _refresh_all(self) -> None:
        for panel in self._plugin_panels:
            if hasattr(panel, "analyze"):
                panel.analyze()
        self.disasm_panel.refresh()
        self.hex_panel.refresh()
        self.cfg_panel.refresh()
        # Reset ROP panel status when a new binary is loaded; scan is user-triggered.
        if self.session.binary:
            self.rop_panel._status.setText(
                f"Ready — {self.session.binary.name}  (press Scan)"
            )
            self.rop_panel._gadgets = []
            self.rop_panel._table.setRowCount(0)
        self.exploit_console.refresh_namespace()
        self.shellcraft_panel.refresh_arch()

    # ── state helpers ─────────────────────────────────────────────────────────

    def _set_paused(self, paused: bool) -> None:
        """paused=True → process stopped, step/continue available."""
        self._act_step.setEnabled(paused)
        self._act_stepov.setEnabled(paused)
        self._act_cont.setEnabled(paused)
        self._act_stop.setEnabled(paused)
        self._act_run.setEnabled(not paused)
        self._act_attach.setEnabled(not paused)

    def _disable_all_debug_actions(self) -> None:
        for act in (self._act_run, self._act_attach, self._act_step,
                    self._act_stepov, self._act_cont, self._act_stop):
            act.setEnabled(False)

    def _reset_to_static(self) -> None:
        self._act_step.setEnabled(False)
        self._act_stepov.setEnabled(False)
        self._act_cont.setEnabled(False)
        self._act_stop.setEnabled(False)
        self._act_run.setEnabled(self.session.binary is not None)
        self._act_restart.setEnabled(self.session.binary is not None)
        self._act_attach.setEnabled(True)
        self._status_mode.setText("static")
        self._status_addr.setText("")
        self.registers_panel.refresh()
        self.stack_panel.clear()

    def _is_dynamic(self) -> bool:
        from backends.gdb_backend import GDBBackend
        return isinstance(self.session.backend, GDBBackend)

    def _noop(self) -> None:
        pass

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
