"""Abstract debugger backend — static and dynamic backends implement this."""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from core.binary import BinaryInfo


@dataclass
class ModuleInfo:
    name: str
    base: int
    size: int
    path: str = ""

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class PageInfo:
    base: int
    size: int
    protection: str     # "r", "rw", "rx", "rwx"

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.end


class DebuggerBackend(ABC):

    # ── loading ───────────────────────────────────────────────────────────────

    @abstractmethod
    def load(self, path: str) -> "BinaryInfo": ...

    # ── process control (dynamic only) ────────────────────────────────────────

    def attach(self, _pid: int) -> None:
        raise NotImplementedError("attach not supported in static mode")

    def spawn(self, _path: str, _args: list[str] | None = None) -> None:
        raise NotImplementedError("spawn not supported in static mode")

    def detach(self) -> None:
        pass

    def set_stop_callback(self, _cb) -> None:
        pass

    def set_log_callback(self, _cb) -> None:
        pass

    # ── memory ────────────────────────────────────────────────────────────────

    @abstractmethod
    def read_memory(self, addr: int, size: int) -> bytes: ...

    def write_memory(self, _addr: int, _data: bytes) -> None:
        raise NotImplementedError

    # ── registers (dynamic only) ──────────────────────────────────────────────

    def get_registers(self) -> dict[str, int]:
        return {}

    # ── breakpoints + execution (dynamic only) ────────────────────────────────

    def set_breakpoint(self, _addr: int) -> None:
        raise NotImplementedError

    def remove_breakpoint(self, _addr: int) -> None:
        raise NotImplementedError

    def step(self) -> None:
        raise NotImplementedError

    def step_over(self) -> None:
        raise NotImplementedError

    def continue_(self) -> None:
        raise NotImplementedError

    # ── process info (overridden by dynamic backend) ──────────────────────────

    def get_modules(self) -> list[ModuleInfo]:
        return []

    def get_memory_pages(self) -> list[PageInfo]:
        return []

    def get_page_at(self, addr: int) -> Optional[PageInfo]:
        for page in self.get_memory_pages():
            if page.contains(addr):
                return page
        return None

    def assemble(self, _code: str) -> bytes:
        raise NotImplementedError
