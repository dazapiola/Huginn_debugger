"""GDB/MI dynamic backend — spawn, breakpoints, step, registers."""
from __future__ import annotations

import os
import pty
import queue
import re
import select
import subprocess
import sys
import threading
from typing import Callable, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backends.base import DebuggerBackend, ModuleInfo, PageInfo

_GDB = "/usr/bin/gdb"

_WANTED_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags",
})


class GDBBackend(DebuggerBackend):

    def __init__(self) -> None:
        self._proc:           Optional[subprocess.Popen] = None
        self._pid:            Optional[int]              = None
        self._binary_info    = None
        self._runtime_base:   Optional[int]              = None
        self._stop_callback:  Optional[Callable[[int], None]] = None

        # Set while spawn() handles a stop internally; _handle_stopped returns early.
        self._startup_handler: Optional[Callable[[], None]] = None
        self._log_callback:   Optional[Callable[[str, str], None]] = None

        self._token      = 0
        self._token_lock = threading.Lock()
        self._pending:    dict[int, queue.Queue] = {}
        self._pending_lock = threading.Lock()

        self._regs:      dict[str, int] = {}
        self._reg_names: dict[int, str] = {}  # GDB register index → name

        self._bpnums:    dict[int, int] = {}  # static_addr → GDB bp number

        self._reader_thread: Optional[threading.Thread] = None

        # PTY for inferior I/O — keeps inferior stdin/stdout off the GDB/MI pipe.
        self._inf_master_fd: Optional[int] = None
        self._inf_slave_fd:  Optional[int] = None
        self._inf_slave_name: str = ""

    # ── callback ──────────────────────────────────────────────────────────────

    def set_stop_callback(self, cb: Callable[[int], None]) -> None:
        self._stop_callback = cb

    def set_log_callback(self, cb: Callable[[str, str], None]) -> None:
        self._log_callback = cb

    # ── binary loading ────────────────────────────────────────────────────────

    def load(self, path: str):
        from core.binary import load as lief_load
        self._binary_info = lief_load(path)
        return self._binary_info

    # ── address translation ───────────────────────────────────────────────────

    def _to_runtime(self, static_addr: int) -> int:
        if self._runtime_base is None or self._binary_info is None:
            return static_addr
        return self._runtime_base + (static_addr - self._binary_info.base_address)

    def _to_static(self, runtime_addr: int) -> int:
        if self._runtime_base is None or self._binary_info is None:
            return runtime_addr
        return self._binary_info.base_address + (runtime_addr - self._runtime_base)

    # ── GDB subprocess ────────────────────────────────────────────────────────

    def _start_gdb(self) -> None:
        # PTY pair: inferior uses slave end, we read inferior output from master.
        master, slave = pty.openpty()
        self._inf_master_fd = master
        self._inf_slave_fd  = slave
        self._inf_slave_name = os.ttyname(slave)

        self._proc = subprocess.Popen(
            [_GDB, "--interpreter=mi2", "--quiet"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self._reader_thread = threading.Thread(target=self._reader, daemon=True)
        self._reader_thread.start()
        threading.Thread(target=self._inf_reader, daemon=True).start()

    def _next_token(self) -> int:
        with self._token_lock:
            self._token += 1
            return self._token

    def _send(self, line: str) -> None:
        if self._proc and self._proc.stdin:
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.flush()

    def _cmd(self, mi_cmd: str, timeout: float = 10.0) -> dict:
        """Send an MI command and block until its token response arrives."""
        tok = self._next_token()
        q: queue.Queue = queue.Queue()
        with self._pending_lock:
            self._pending[tok] = q
        self._send(f"{tok}{mi_cmd}")
        try:
            result = q.get(timeout=timeout)
        except queue.Empty:
            result = {"class": "timeout", "raw": ""}
        with self._pending_lock:
            self._pending.pop(tok, None)
        return result

    # ── reader threads ────────────────────────────────────────────────────────

    def _inf_reader(self) -> None:
        """Read inferior stdout/stderr from the PTY master and forward to log."""
        mfd = self._inf_master_fd
        if mfd is None:
            return
        buf = b""
        while True:
            try:
                r, _, _ = select.select([mfd], [], [], 0.5)
            except (ValueError, OSError):
                break
            if not r:
                continue
            try:
                chunk = os.read(mfd, 4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.rstrip(b"\r").decode("utf-8", errors="replace").strip()
                if text and self._log_callback:
                    self._log_callback(text, "out")

    def _reader(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            self._dispatch(raw.rstrip("\n"))

    def _dispatch(self, line: str) -> None:
        if not line or line == "(gdb)":
            return

        # Synchronous response: TOKEN^class[,results]
        m = re.match(r'^(\d+)\^(done|error|running|connected|exit)(,(.*))?$', line)
        if m:
            tok = int(m.group(1))
            cls = m.group(2)
            raw = m.group(4) or ""
            with self._pending_lock:
                q = self._pending.get(tok)
            if q:
                q.put({"class": cls, "raw": raw})
            return

        # Async stop — handle in a separate thread so the reader keeps reading.
        if line.startswith("*stopped"):
            threading.Thread(target=self._handle_stopped, args=(line,), daemon=True).start()
            return

        # GDB console output — forward to log as-is.
        if line.startswith('~"') or line.startswith('@"'):
            kind = "out" if line.startswith('@"') else "gdb"
            raw = line[2:]
            if raw.endswith('"'):
                raw = raw[:-1]
            text = raw.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\').replace('\\t', '\t')
            if self._log_callback:
                for part in text.splitlines():
                    part = part.strip()
                    if part:
                        self._log_callback(part, kind)
            return

        # *running, =notify, &log — no action needed.

    def _handle_stopped(self, line: str) -> None:
        # During spawn() startup phases, just signal the waiting event.
        if self._startup_handler is not None:
            self._startup_handler()
            return

        m = re.search(r'addr="(0x[0-9a-fA-F]+)"', line)
        runtime_pc = int(m.group(1), 16) if m else 0

        if self._pid is None:
            self._resolve_pid()

        self._fetch_registers()
        if not runtime_pc:
            runtime_pc = self._regs.get("rip", 0)

        static_pc = self._to_static(runtime_pc)
        if self._stop_callback:
            self._stop_callback(static_pc)

    # ── register helpers ──────────────────────────────────────────────────────

    def _init_reg_names(self) -> None:
        resp = self._cmd("-data-list-register-names")
        m = re.search(r'register-names=\[([^\]]*)\]', resp["raw"])
        if not m:
            return
        names = re.findall(r'"([^"]*)"', m.group(1))
        self._reg_names = {i: n for i, n in enumerate(names) if n}

    def _fetch_registers(self) -> None:
        if not self._reg_names:
            self._init_reg_names()
        resp = self._cmd("-data-list-register-values x")
        regs: dict[str, int] = {}
        for m in re.finditer(r'\{number="(\d+)",value="(0x[0-9a-fA-F]+)"\}', resp["raw"]):
            idx  = int(m.group(1))
            name = self._reg_names.get(idx, "")
            if name in _WANTED_REGS:
                try:
                    regs[name] = int(m.group(2), 16)
                except ValueError:
                    pass
        self._regs = regs

    # ── attach / spawn ────────────────────────────────────────────────────────

    def attach(self, pid: int) -> None:
        self._start_gdb()

        if self._binary_info:
            self._cmd(f'-file-exec-and-symbols "{self._binary_info.path}"', timeout=15)

        if self._inf_slave_name:
            self._cmd(f'-gdb-set inferior-tty {self._inf_slave_name}')

        if self._log_callback:
            self._log_callback(f"Attaching to PID {pid}…", "evt")

        # -target-attach sends ^done, then *stopped once the process is paused.
        stop_ev = threading.Event()
        self._startup_handler = lambda: stop_ev.set()
        resp = self._cmd(f'-target-attach {pid}', timeout=15)
        if resp.get("class") == "error":
            self._startup_handler = None
            raise RuntimeError(resp.get("raw", "attach failed"))
        stop_ev.wait(timeout=15)
        self._startup_handler = None

        self._pid = pid

        if self._binary_info:
            if self._binary_info.base_address == 0:
                self._runtime_base = self._read_runtime_base_from_maps(self._binary_info.path)
            else:
                self._runtime_base = self._binary_info.base_address

        if self._log_callback:
            self._log_callback(f"Attached to PID {pid}", "evt")

        self._fetch_registers()
        runtime_pc = self._regs.get("rip", 0)
        if self._stop_callback:
            self._stop_callback(self._to_static(runtime_pc))

    def spawn(self, path: str, args: list[str] | None = None) -> None:
        self._start_gdb()
        self._cmd(f'-file-exec-and-symbols "{path}"', timeout=15)

        # Redirect inferior I/O to PTY — keeps the GDB/MI pipe free of program output
        # and prevents the inferior's read() from consuming our MI commands.
        if self._inf_slave_name:
            self._cmd(f'-gdb-set inferior-tty {self._inf_slave_name}')

        if args:
            self._cmd(f'-exec-arguments {" ".join(args)}')

        is_pie = self._binary_info is not None and self._binary_info.base_address == 0
        if self._log_callback:
            self._log_callback(f"Spawning {os.path.basename(path)}  ({'PIE' if is_pie else 'non-PIE'})", "evt")
        if is_pie:
            self._spawn_pie(path)
        else:
            self._spawn_nonpie()

    def _spawn_nonpie(self) -> None:
        if self._binary_info:
            self._runtime_base = self._binary_info.base_address
            self._cmd(f'-break-insert -t *{hex(self._binary_info.entry_point)}')

        stop_ev = threading.Event()
        self._startup_handler = lambda: stop_ev.set()
        self._cmd("-exec-run", timeout=15)
        stop_ev.wait(timeout=30)
        self._startup_handler = None

        self._resolve_pid()
        if self._log_callback and self._pid:
            self._log_callback(f"Process started, PID {self._pid}", "evt")
        self._fetch_registers()
        runtime_pc = self._regs.get("rip", 0)
        if self._stop_callback:
            self._stop_callback(self._to_static(runtime_pc))

    def _spawn_pie(self, path: str) -> None:
        # Phase 1: starti — stop at first instruction (inside ld.so) to find runtime base.
        starti_ev = threading.Event()
        self._startup_handler = lambda: starti_ev.set()
        self._cmd('-interpreter-exec console "starti"', timeout=30)
        starti_ev.wait(timeout=30)
        self._startup_handler = None

        self._resolve_pid()
        self._runtime_base = self._read_runtime_base_from_maps(path)

        # Phase 2: temp bp at runtime entry, continue to it.
        if self._binary_info and self._runtime_base is not None:
            # For PIE: base_address == 0, so entry_point IS the RVA.
            entry_runtime = self._runtime_base + self._binary_info.entry_point
            self._cmd(f'-break-insert -t *{hex(entry_runtime)}')

        entry_ev = threading.Event()
        self._startup_handler = lambda: entry_ev.set()
        self._cmd("-exec-continue", timeout=10)
        entry_ev.wait(timeout=30)
        self._startup_handler = None

        if self._log_callback and self._pid:
            self._log_callback(f"Process started, PID {self._pid}", "evt")
        self._fetch_registers()
        runtime_pc = self._regs.get("rip", 0)
        if self._stop_callback:
            self._stop_callback(self._to_static(runtime_pc))

    def _resolve_pid(self) -> None:
        resp = self._cmd("-list-thread-groups")
        m = re.search(r'pid="(\d+)"', resp["raw"])
        if m:
            self._pid = int(m.group(1))

    def _read_runtime_base_from_maps(self, binary_path: str) -> Optional[int]:
        if not self._pid:
            return None
        abs_path = os.path.realpath(binary_path)
        try:
            with open(f"/proc/{self._pid}/maps") as f:
                for line in f:
                    if abs_path in line or binary_path in line:
                        parts = line.split()
                        if parts:
                            try:
                                start = int(parts[0].split("-")[0], 16)
                                if start > 0:
                                    return start
                            except ValueError:
                                pass
        except OSError:
            pass
        return None

    # ── detach ────────────────────────────────────────────────────────────────

    def detach(self) -> None:
        try:
            self._cmd("-exec-interrupt", timeout=2)
        except Exception:
            pass
        try:
            self._cmd('-interpreter-exec console "kill"', timeout=3)
        except Exception:
            pass
        if self._proc:
            try:
                self._send("-gdb-exit")
                self._proc.wait(timeout=2)
            except Exception:
                pass
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None
        self._pid  = None

        for fd in (self._inf_master_fd, self._inf_slave_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._inf_master_fd = None
        self._inf_slave_fd  = None

    # ── execution control ─────────────────────────────────────────────────────

    def continue_(self) -> None:
        self._cmd("-exec-continue")

    def step(self) -> None:
        self._cmd("-exec-step-instruction")

    def step_over(self) -> None:
        self._cmd("-exec-next-instruction")

    # ── breakpoints ───────────────────────────────────────────────────────────

    def set_breakpoint(self, addr: int) -> None:
        runtime_addr = self._to_runtime(addr)
        resp = self._cmd(f"-break-insert *{hex(runtime_addr)}")
        m = re.search(r'number="(\d+)"', resp["raw"])
        if m:
            self._bpnums[addr] = int(m.group(1))

    def remove_breakpoint(self, addr: int) -> None:
        bpnum = self._bpnums.pop(addr, None)
        if bpnum is not None:
            self._cmd(f"-break-delete {bpnum}")

    # ── memory ────────────────────────────────────────────────────────────────

    def read_memory(self, addr: int, size: int) -> bytes:
        resp = self._cmd(f"-data-read-memory-bytes {hex(addr)} {size}")
        m = re.search(r'contents="([0-9a-fA-F]+)"', resp["raw"])
        if m:
            try:
                return bytes.fromhex(m.group(1))
            except ValueError:
                pass
        return bytes(size)

    def write_memory(self, addr: int, data: bytes) -> None:
        self._cmd(f"-data-write-memory-bytes {hex(addr)} {data.hex()}")

    # ── registers ─────────────────────────────────────────────────────────────

    def get_registers(self) -> dict[str, int]:
        return dict(self._regs)

    # ── process info ──────────────────────────────────────────────────────────

    def get_modules(self) -> list[ModuleInfo]:
        if not self._pid:
            return []
        seen: dict[str, list[tuple[int, int]]] = {}
        try:
            with open(f"/proc/{self._pid}/maps") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue
                    path = parts[5]
                    if not path.startswith("/"):
                        continue
                    lo, hi = parts[0].split("-")
                    seen.setdefault(path, []).append((int(lo, 16), int(hi, 16)))
        except OSError:
            return []
        result: list[ModuleInfo] = []
        for path, ranges in seen.items():
            base = min(r[0] for r in ranges)
            top  = max(r[1] for r in ranges)
            result.append(ModuleInfo(
                name=os.path.basename(path), base=base, size=top - base, path=path,
            ))
        return result

    def get_memory_pages(self) -> list[PageInfo]:
        if not self._pid:
            return []
        pages: list[PageInfo] = []
        try:
            with open(f"/proc/{self._pid}/maps") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    lo, hi = parts[0].split("-")
                    flags = parts[1]
                    prot  = ""
                    if flags[0] == "r": prot += "r"
                    if flags[1] == "w": prot += "w"
                    if flags[2] == "x": prot += "x"
                    pages.append(PageInfo(
                        base=int(lo, 16), size=int(hi, 16) - int(lo, 16),
                        protection=prot or "---",
                    ))
        except OSError:
            pass
        return pages

    # ── assemble ──────────────────────────────────────────────────────────────

    def assemble(self, code: str) -> bytes:
        try:
            import keystone  # type: ignore[import-untyped]
        except ImportError:
            return b""
        try:
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            enc, _ = ks.asm(code)
            return bytes(enc)
        except Exception:
            return b""
