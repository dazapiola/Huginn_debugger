#!/usr/bin/env python3
"""
Fase 1 — verificación del core engine (sin UI).
Carga el crackme de clase1, imprime disasm y CFG por consola.
"""
import sys
import os

# Asegurar que el root del proyecto esté en el path
sys.path.insert(0, os.path.dirname(__file__))

from core.session import Session
from backends.static_backend import StaticBackend

CRACKME = os.path.join(os.path.dirname(__file__), "..", "clase1", "crackme")


def separator(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print('─' * 60)


def test_binary_load(session: Session) -> None:
    separator("Binary info (LIEF)")
    b = session.binary
    assert b is not None
    print(f"  file     : {b.path}")
    print(f"  format   : {b.fmt}")
    print(f"  arch     : {b.arch} / {b.bits}bit")
    print(f"  entry    : {hex(b.entry_point)}")
    print(f"  base     : {hex(b.base_address)}")
    print(f"  sections : {len(b.sections)}")
    print(f"  segments : {len(b.segments)}")
    print(f"  symbols  : {len(b.symbols)}")
    print()
    for sec in b.sections:
        print(f"    [{sec.flags:3s}]  {sec.name:20s}  va={hex(sec.virtual_address):12s}  sz={sec.size}")
    print()
    for seg in b.segments:
        print(f"    [{seg.flags:3s}]  {seg.kind:10s}  va={hex(seg.virtual_address):12s}  phys={seg.physical_size}")


def test_disasm(session: Session) -> None:
    separator("Disassembly (Capstone) — first 20 instructions from entry point")
    insns = session.disassemble_at(session.current_address or 0, count=20)
    for i in insns:
        bp = "●" if i.address in session.breakpoints else " "
        flags = []
        if i.is_jump: flags.append("J")
        if i.is_call: flags.append("C")
        if i.is_ret:  flags.append("R")
        flag_str = "".join(flags)
        tgt = f" → {hex(i.jump_target)}" if i.jump_target else ""
        print(f"  {bp} {hex(i.address):<14s} {i.hex_bytes:<20s} {i.mnemonic} {i.op_str}{tgt}  {flag_str}")


def test_read_memory(session: Session) -> None:
    separator("Memory read — 32 bytes at entry point")
    entry = session.binary.entry_point  # type: ignore[union-attr]
    data = session.backend.read_memory(entry, 32)
    hex_rows = [data[i:i+16].hex(" ") for i in range(0, len(data), 16)]
    for row_idx, row in enumerate(hex_rows):
        print(f"  {hex(entry + row_idx * 16):14s}  {row}")


def test_cfg(session: Session) -> None:
    separator("CFG (networkx) — basic blocks from entry point")
    entry = session.binary.entry_point  # type: ignore[union-attr]
    G = session.build_cfg_at(entry, max_bytes=0x100)
    assert G is not None
    print(f"  Nodes (basic blocks): {G.number_of_nodes()}")
    print(f"  Edges (branches):     {G.number_of_edges()}")
    print()
    for node_addr in sorted(G.nodes):
        block = G.nodes[node_addr].get("block")
        if block is None:
            continue
        out_edges = [(hex(v), d.get("kind", "?")) for _, v, d in G.out_edges(node_addr, data=True)]
        print(f"  Block {hex(block.start_addr):<14s} ({len(block.instructions)} insns)")
        for insn in block.instructions:
            print(f"        {hex(insn.address):<12s}  {insn.mnemonic} {insn.op_str}")
        if out_edges:
            print(f"        → {out_edges}")
        print()


def test_pages(session: Session) -> None:
    separator("Memory pages (from segments/sections)")
    for page in session.backend.get_memory_pages():
        print(f"  [{page.protection:3s}]  {hex(page.base):14s} – {hex(page.end):14s}  ({page.size} bytes)")


def test_modules(session: Session) -> None:
    separator("Modules")
    for mod in session.backend.get_modules():
        print(f"  {mod.name:30s}  base={hex(mod.base)}  size={mod.size}  path={mod.path}")


def main() -> None:
    if not os.path.exists(CRACKME):
        print(f"[!] Binary not found: {CRACKME}")
        print("    Asegúrate de haber compilado clase1/crackme primero.")
        sys.exit(1)

    session = Session()
    session.setup(StaticBackend())

    print(f"\n[+] Loading: {CRACKME}")
    session.load(CRACKME)

    test_binary_load(session)
    test_disasm(session)
    test_read_memory(session)
    test_cfg(session)
    test_pages(session)
    test_modules(session)

    separator("Fase 1 — OK")
    print("  Todos los módulos del core funcionan correctamente.\n")


if __name__ == "__main__":
    main()
