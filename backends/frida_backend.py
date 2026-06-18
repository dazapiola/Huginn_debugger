"""Frida dynamic backend — spawn/attach, breakpoints, live registers."""
from __future__ import annotations
import os
import sys
import threading
from typing import Callable, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import frida

from backends.base import DebuggerBackend, ModuleInfo, PageInfo

_AGENT = os.path.join(os.path.dirname(__file__), "..", "frida_agent", "agent.js")


class FridaBackend(DebuggerBackend):
    """Dynamic backend using Frida for live process debugging."""

    def __init__(self) -> None:
        self._device:          Optional[frida.core.Device]  = None
        self._session:         Optional[frida.core.Session] = None
        self._script:          Optional[frida.core.Script]  = None
        self._rpc              = None                       # set by _load_agent()
        self._pid:             Optional[int]                = None
        self._regs:            dict[str, int]               = {}
        self._last_bp:         Optional[str]                = None
        self._bp_event         = threading.Event()
        self._binary_info      = None                       # set by load()
        self._stop_callback:   Optional[Callable[[int], None]] = None

    def set_stop_callback(self, cb: Callable[[int], None]) -> None:
        self._stop_callback = cb

    # ── loading ───────────────────────────────────────────────────────────────

    def load(self, path: str):
        from core.binary import load as lief_load
        self._binary_info = lief_load(path)
        return self._binary_info

    # ── process control ───────────────────────────────────────────────────────

    def spawn(self, path: str, args: list[str] | None = None) -> None:  # type: ignore[override]
        self._device = frida.get_local_device()
        pid = self._device.spawn([path] + (args or []))
        self._pid = pid
        self._session = self._device.attach(pid)
        self._load_agent()
        if self._binary_info:
            self._rpc.set_breakpoint(hex(self._binary_info.entry_point))
        self._device.resume(pid)

    def attach(self, pid: int) -> None:
        self._device = frida.get_local_device()
        self._pid = pid
        self._session = self._device.attach(pid)
        self._load_agent()

    def detach(self) -> None:
        for cleanup in (
            lambda: self._script and self._script.unload(),
            lambda: self._session and self._session.detach(),
        ):
            try:
                cleanup()
            except Exception:
                pass
        self._script = self._session = self._pid = self._rpc = None

    def _load_agent(self) -> None:
        with open(_AGENT) as f:
            source = f.read()
        self._script = self._session.create_script(source)  # type: ignore[union-attr]
        self._script.on("message", self._on_message)
        self._script.load()
        self._rpc = self._script.exports_sync  # type: ignore[attr-defined]

    def _on_message(self, message: dict, _data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if payload.get("type") == "bp_hit":
                raw = payload.get("regs", {})
                parsed: dict[str, int] = {}
                for k, v in raw.items():
                    try:
                        parsed[k] = int(str(v), 16)
                    except (ValueError, TypeError):
                        parsed[k] = 0
                self._regs = parsed
                self._last_bp = payload.get("addr")
                self._bp_event.set()
                if self._stop_callback:
                    rip = self._regs.get("rip", 0)
                    self._stop_callback(rip)
            elif payload.get("type") == "bp_error":
                print(f"[frida] bp_error @ {payload.get('addr')}: {payload.get('msg')}")
        elif message.get("type") == "error":
            print(f"[frida] script error: {message.get('description')}")

    # ── execution flow ────────────────────────────────────────────────────────

    def wait_for_event(self, timeout: float = 10.0) -> bool:
        """Block until a breakpoint fires. Returns True if one fired."""
        return self._bp_event.wait(timeout)

    def continue_(self) -> None:
        self._bp_event.clear()
        if self._script:
            self._script.post({"type": "continue"})  # type: ignore[union-attr]

    def step(self) -> None:
        rip = self._regs.get("rip", 0)
        if not rip or not self._rpc:
            return
        raw = self.read_memory(rip, 15)
        next_addrs = self._next_addrs(rip, raw)
        for a in next_addrs:
            self._rpc.set_breakpoint(hex(a))
        self._bp_event.clear()
        self._script.post({"type": "continue"})  # type: ignore[union-attr]
        self._bp_event.wait(5.0)
        for a in next_addrs:
            self._rpc.remove_breakpoint(hex(a))

    def step_over(self) -> None:
        self.step()

    def _next_addrs(self, rip: int, raw: bytes) -> list[int]:
        try:
            import capstone
            import capstone.x86 as x86
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            cs.detail = True
            insns = list(cs.disasm(raw, rip, 1))
            if not insns:
                return [rip + 1]
            insn = insns[0]
            fall = insn.address + insn.size
            groups = set(insn.groups)
            if capstone.CS_GRP_RET in groups:
                return []  # can't predict ret target without stack read
            if capstone.CS_GRP_JUMP in groups:
                for op in insn.operands:
                    if op.type == x86.X86_OP_IMM:
                        target = op.imm
                        # conditional: both paths
                        if capstone.CS_GRP_BRANCH_RELATIVE in groups:
                            return [fall, target]
                        return [target]
                return [fall]   # indirect jump — fall back
            return [fall]
        except Exception:
            return [rip + 1]

    # ── memory ────────────────────────────────────────────────────────────────

    def read_memory(self, addr: int, size: int) -> bytes:
        if self._rpc:
            try:
                data = self._rpc.read_memory(hex(addr), size)
                if data is not None:
                    return bytes(data)
            except Exception:
                pass
        return bytes(size)

    def write_memory(self, addr: int, data: bytes) -> None:
        if self._rpc:
            self._rpc.write_memory(hex(addr), list(data))

    # ── registers ────────────────────────────────────────────────────────────

    def get_registers(self) -> dict[str, int]:
        return dict(self._regs)

    # ── breakpoints ───────────────────────────────────────────────────────────

    def set_breakpoint(self, addr: int) -> None:
        if self._rpc:
            self._rpc.set_breakpoint(hex(addr))

    def remove_breakpoint(self, addr: int) -> None:
        if self._rpc:
            self._rpc.remove_breakpoint(hex(addr))

    # ── process info ─────────────────────────────────────────────────────────

    def get_modules(self) -> list[ModuleInfo]:
        if not self._rpc:
            return []
        try:
            return [
                ModuleInfo(name=m["name"], base=int(m["base"], 16),
                           size=m["size"], path=m["path"])
                for m in self._rpc.get_modules()
            ]
        except Exception:
            return []

    def get_memory_pages(self) -> list[PageInfo]:
        if not self._rpc:
            return []
        try:
            return [
                PageInfo(base=int(r["base"], 16), size=r["size"], protection=r["protection"])
                for r in self._rpc.get_ranges()
            ]
        except Exception:
            return []

    def assemble(self, code: str) -> bytes:
        try:
            import keystone
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            enc, _ = ks.asm(code)
            return bytes(enc)
        except Exception:
            return b""
