"""Bridge between Huginn session and mona.py's immlib Debugger API."""
from __future__ import annotations
import sys
import types
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from core.session import Session

_immlib_injected = False


def _ensure_immlib_stub() -> None:
    global _immlib_injected
    if _immlib_injected or "immlib" in sys.modules:
        return
    stub = types.ModuleType("immlib")

    class _StubDbg:
        def log(self, msg="", *a, **kw):
            pass
        def logLines(self, msg, **kw):
            pass
        def getDebuggedName(self):
            return "stub"
        def getDebuggedPid(self):
            return 0
        def getOsVersion(self):
            return "lin"
        def getRegs(self):
            return {}
        def createLogWindow(self):
            pass
        def setStatusBar(self, msg):
            pass
        def error(self, msg, **kw):
            pass

    class _StubBpHook:
        def add(self, name, addr):
            pass
        def logln(self, msg):
            pass

    stub.Debugger = _StubDbg
    stub.LogBpHook = _StubBpHook
    sys.modules["immlib"] = stub
    _immlib_injected = True


class MonaBridge:
    """Implements the immlib.Debugger interface backed by our Session."""

    def __init__(self, session: "Session", log_cb: Callable[[str], None]) -> None:
        self._session = session
        self._log = log_cb

    # ── logging ──────────────────────────────────────────────────────────────

    def log(self, msg="", *args, **kw) -> None:
        self._log(str(msg))

    def logLines(self, msg, **kw) -> None:
        for line in str(msg).split("\n"):
            self._log(line)

    def error(self, msg, **kw) -> None:
        self._log(f"[ERR] {msg}")

    # ── process info ──────────────────────────────────────────────────────────

    def getDebuggedName(self) -> str:
        if self._session.binary:
            import os
            return os.path.basename(self._session.binary.path)
        return "unknown"

    def getDebuggedPid(self) -> int:
        return getattr(self._session.backend, "_pid", 1234) or 1234

    # ── registers ─────────────────────────────────────────────────────────────

    def getRegs(self) -> dict:
        try:
            return {k.upper(): v for k, v in self._session.backend.get_registers().items()}
        except Exception:
            return {}

    # ── memory ────────────────────────────────────────────────────────────────

    def readMemory(self, addr: int, size: int) -> bytes:
        try:
            return self._session.backend.read_memory(addr, size)
        except Exception:
            return b"\x00" * size

    def getPageSize(self) -> int:
        return 4096

    # ── modules ───────────────────────────────────────────────────────────────

    def getAllModules(self) -> dict:
        try:
            return {m.name: _MonaModule(m) for m in self._session.backend.get_modules()}
        except Exception:
            return {}

    def getModule(self, name: str):
        return self.getAllModules().get(name)

    def getAddress(self, addr: int):
        try:
            page = self._session.backend.get_page_at(addr)
            if page:
                return _MonaPage(page)
        except Exception:
            pass
        return None

    # ── stubs ─────────────────────────────────────────────────────────────────

    def searchCommands(self, *args):
        return []

    def getOsVersion(self) -> str:
        return "lin"

    def isHEAPBlock(self, addr: int) -> bool:
        return False

    def getJmp(self, addr: int):
        return None

    def createLogWindow(self) -> None:
        pass

    def setStatusBar(self, msg: str) -> None:
        pass

    def createTable(self, *args, **kw):
        return None

    def nativeCommand(self, cmd: str) -> str:
        return ""


class _MonaModule:
    def __init__(self, mod) -> None:
        self._mod = mod

    def getBaseAddress(self) -> int:
        return self._mod.base

    def getSize(self) -> int:
        return self._mod.size

    def getName(self) -> str:
        return self._mod.name

    def getPath(self) -> str:
        return getattr(self._mod, "path", self._mod.name)

    def isAslr(self) -> bool:
        return False

    def isSafeSEH(self) -> bool:
        return False

    def isRebase(self) -> bool:
        return False

    def isNXCompat(self) -> bool:
        return False

    def isOsDll(self) -> bool:
        return False


class _MonaPage:
    def __init__(self, page) -> None:
        self._page = page

    def isExecutable(self) -> bool:
        return "x" in self._page.protection

    def isReadable(self) -> bool:
        return "r" in self._page.protection

    def isWriteable(self) -> bool:
        return "w" in self._page.protection


def get_mona():
    """Return the mona module, importing it (and injecting stub) on first call."""
    _ensure_immlib_stub()
    import plugins.mona.vendor.mona as m
    return m
