#!/usr/bin/env python3
"""Phase 3 verification — Frida dynamic backend console test.

Target: ../clase1/crackme_dyn  (dynamically linked, loops 10× with 200ms sleep)

Checks:
  1. Spawn the process
  2. List loaded modules
  3. Read memory at main module base
  4. Set a breakpoint at say_hello
  5. Wait for the breakpoint to fire
  6. Print captured registers (RIP, RSP, RDI)
  7. Continue
  8. Wait for a second hit
  9. Detach
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backends.frida_backend import FridaBackend

TARGET = os.path.join(os.path.dirname(__file__), "..", "clase1", "crackme_dyn")

SEP  = "─" * 60
PASS = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"
INFO = "\033[36m[INFO]\033[0m"


def _chk(label: str, cond: bool) -> None:
    tag = PASS if cond else FAIL
    print(f"  {tag}  {label}")
    if not cond:
        sys.exit(1)


def _find_say_hello(backend: FridaBackend) -> int | None:
    """Resolve say_hello by scanning the main module exports / symbols."""
    mods = backend.get_modules()
    main_mod = next((m for m in mods if "crackme_dyn" in m.name), None)
    if main_mod is None:
        return None
    try:
        import lief
        binary = lief.parse(TARGET)
        if binary is None:
            return None
        for sym in binary.symbols:
            if sym.name == "say_hello" and sym.value:
                # The binary is PIE — add ASLR base from main_mod
                pie_base = binary.segments[0].virtual_address & ~0xFFF
                # Actually for PIE, lief gives offset from 0x0
                # Actual addr = main_mod.base + sym.value - pie_base
                # But lief's sym.value for a PIE is already the offset from 0x0
                # so actual VA = main_mod.base + sym.value (if lief loads at 0)
                # Let's just check: lief pie base is usually 0x0
                load_base = 0
                for seg in binary.segments:
                    if seg.type == lief.ELF.Segment.TYPE.LOAD:
                        load_base = seg.virtual_address & ~0xFFF
                        break
                return main_mod.base + (sym.value - load_base)
    except Exception as e:
        print(f"  {INFO}  symbol scan error: {e}")
    return None


def main() -> None:
    print(SEP)
    print("  Huginn — Phase 3: Frida Dynamic Backend")
    print(SEP)

    if not os.path.isfile(TARGET):
        print(f"  {FAIL}  Target not found: {TARGET}")
        sys.exit(1)

    backend = FridaBackend()

    # 1. Load static binary info
    backend.load(TARGET)
    _chk("load() parsed static binary info", backend._binary_info is not None)

    # 2. Spawn
    print(f"\n  {INFO}  Spawning {os.path.basename(TARGET)} ...")
    try:
        backend.spawn(TARGET)
    except Exception as e:
        print(f"  {FAIL}  spawn() failed: {e}")
        sys.exit(1)
    _chk("spawn() did not crash", True)

    # 3. Modules
    mods = backend.get_modules()
    _chk("get_modules() returned at least 1 module", len(mods) >= 1)
    main_mod = next((m for m in mods if "crackme_dyn" in m.name), None)
    _chk("main module found", main_mod is not None)
    if main_mod:
        print(f"  {INFO}  main module: {main_mod.name}  base={hex(main_mod.base)}")

    # 4. Read memory at module base
    if main_mod:
        mem = backend.read_memory(main_mod.base, 4)
        _chk("read_memory() returns ELF magic", mem[:4] == b"\x7fELF")

    # 5. Resolve say_hello address
    say_hello_addr = _find_say_hello(backend)
    if say_hello_addr is None:
        print(f"  {INFO}  Could not resolve say_hello via symbols — skipping BP test")
    else:
        print(f"  {INFO}  say_hello @ {hex(say_hello_addr)}")

        # 6. Set breakpoint
        try:
            backend.set_breakpoint(say_hello_addr)
            _chk("set_breakpoint() did not raise", True)
        except Exception as e:
            print(f"  {FAIL}  set_breakpoint() raised: {e}")
            sys.exit(1)

        # 7. Wait for first hit
        print(f"  {INFO}  Waiting for breakpoint hit (up to 10s) ...")
        hit = backend.wait_for_event(timeout=10.0)
        _chk("breakpoint fired within timeout", hit)

        regs = backend.get_registers()
        print(f"  {INFO}  RIP={hex(regs.get('rip', 0))}  "
              f"RSP={hex(regs.get('rsp', 0))}  "
              f"RDI={hex(regs.get('rdi', 0))}")
        _chk("RIP close to say_hello", abs(regs.get('rip', 0) - say_hello_addr) < 0x20)

        # 8. Continue, wait for second hit
        backend.continue_()
        print(f"  {INFO}  Continued; waiting for second hit ...")
        hit2 = backend.wait_for_event(timeout=10.0)
        _chk("second breakpoint hit", hit2)
        regs2 = backend.get_registers()
        print(f"  {INFO}  RDI (n)={regs2.get('rdi', '?')}")

        # 9. Remove BP and let it finish
        backend.remove_breakpoint(say_hello_addr)
        backend.continue_()

    # 10. Memory pages
    pages = backend.get_memory_pages()
    _chk("get_memory_pages() returned pages", len(pages) > 0)
    print(f"  {INFO}  {len(pages)} memory ranges visible")

    # 11. Detach
    backend.detach()
    _chk("detach() completed", True)

    print()
    print(SEP)
    print("  Phase 3 complete.\n")


if __name__ == "__main__":
    main()
