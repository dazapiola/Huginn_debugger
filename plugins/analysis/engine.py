"""Analysis engine — extracts labels and detects loops from a loaded binary."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.session import Session


def run(session: "Session") -> None:
    """Populate session.labels and session.loop_headers from the loaded binary."""
    b = session.binary
    if b is None:
        return

    session.labels = _collect_labels(session)
    session.loop_headers = _detect_loops(session)


def _collect_labels(session: "Session") -> dict[int, str]:
    b = session.binary
    assert b is not None

    labels: dict[int, str] = {}

    # Named symbols from the binary (includes PLT stubs, exports, debug info)
    for sym in b.symbols:
        if sym.address and sym.name:
            clean = _clean_name(sym.name)
            if clean:
                labels[sym.address] = clean

    # Fall back: mark the entry point if it has no label
    if b.entry_point not in labels:
        labels[b.entry_point] = "_start"

    return labels


def _detect_loops(session: "Session") -> set[int]:
    """Find loop header addresses by detecting backward jumps in all code sections."""
    b = session.binary
    if b is None or session._cs is None:
        return set()

    from core.disasm import disassemble

    headers: set[int] = set()

    for sec in b.sections:
        if "x" not in sec.flags or not sec.content:
            continue
        insns = disassemble(session._cs, sec.content, sec.virtual_address, max_insns=20000)
        insn_addrs = {i.address for i in insns}
        for insn in insns:
            if insn.is_jump and insn.jump_target:
                # Backward jump whose target is in the same section = loop back edge
                if insn.jump_target < insn.address and insn.jump_target in insn_addrs:
                    headers.add(insn.jump_target)

    return headers


def _clean_name(name: str) -> str:
    """Strip version suffixes and filter out noise symbols."""
    # Drop versioned symbols like "printf@@GLIBC_2.2.5"
    name = name.split("@@")[0].split("@")[0]
    # Skip empty, single-char, or pure-number names
    if len(name) <= 1 or name.isdigit():
        return ""
    # Skip compiler-internal prefixes that are rarely meaningful
    if name.startswith("$") or name.startswith("."):
        return ""
    return name
