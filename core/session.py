"""Global session state: active backend, binary, breakpoints, disassembler."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    import capstone
    from backends.base import DebuggerBackend
    from core.binary import BinaryInfo
    from core.disasm import Instruction


@dataclass
class Session:
    binary: Optional["BinaryInfo"] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    breakpoints: set[int] = field(default_factory=set)
    current_address: Optional[int] = None

    # backend and disassembler are set via setup()
    _backend: Optional["DebuggerBackend"] = field(default=None, repr=False)
    _cs: Optional["capstone.Cs"] = field(default=None, repr=False)
    _mona_log_handlers: list[Callable[[str], None]] = field(
        default_factory=list, repr=False
    )
    _stop_listeners: list[Callable[[int], None]] = field(
        default_factory=list, repr=False
    )

    def setup(self, backend: "DebuggerBackend") -> None:
        self._backend = backend
        if hasattr(backend, "set_stop_callback"):
            backend.set_stop_callback(self.notify_stopped)

    @property
    def backend(self) -> "DebuggerBackend":
        if self._backend is None:
            raise RuntimeError("No backend attached — call session.setup(backend) first")
        return self._backend

    def load(self, path: str) -> "BinaryInfo":
        from core import disasm as _disasm
        self.binary = self.backend.load(path)
        assert self.binary is not None
        self._cs = _disasm.create_disassembler(self.binary.arch, self.binary.bits)
        self.current_address = self.binary.entry_point
        return self.binary

    def disassemble_at(self, addr: int, count: int = 50) -> list["Instruction"]:
        if self._cs is None or self.binary is None:
            return []
        from core import disasm as _disasm
        data = self.backend.read_memory(addr, count * 16)
        return _disasm.disassemble(self._cs, data, addr, max_insns=count)

    def build_cfg_at(self, addr: int, max_bytes: int = 0x2000):
        if self._cs is None:
            return None
        from core.cfg import build_cfg
        data = self.backend.read_memory(addr, max_bytes)
        return build_cfg(self._cs, data, addr, max_bytes=max_bytes)

    # ── stop event ───────────────────────────────────────────────────────────

    def notify_stopped(self, rip: int) -> None:
        """Called from any thread when the process pauses (breakpoint / step)."""
        self.current_address = rip
        for fn in self._stop_listeners:
            fn(rip)

    def on_stopped(self, fn: Callable[[int], None]) -> None:
        self._stop_listeners.append(fn)

    # ── mona logging bridge ───────────────────────────────────────────────────

    def mona_log(self, msg: str) -> None:
        for handler in self._mona_log_handlers:
            handler(msg)

    def add_mona_log_handler(self, fn: Callable[[str], None]) -> None:
        self._mona_log_handlers.append(fn)
