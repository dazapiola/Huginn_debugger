"""Control Flow Graph builder using Capstone instruction groups."""
from __future__ import annotations
from dataclasses import dataclass, field
import capstone
import networkx as nx

from .disasm import Instruction, disassemble


@dataclass
class BasicBlock:
    start_addr: int
    end_addr: int       # exclusive (start of next instruction after last in block)
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def size(self) -> int:
        return self.end_addr - self.start_addr

    @property
    def last(self) -> Instruction | None:
        return self.instructions[-1] if self.instructions else None

    def __repr__(self) -> str:
        return f"BB(0x{self.start_addr:x}–0x{self.end_addr:x}, {len(self.instructions)} insns)"


def build_cfg(cs: capstone.Cs, data: bytes, base_addr: int,
              max_bytes: int = 0x2000) -> nx.DiGraph:
    """
    Build a CFG as a networkx DiGraph.
    Nodes are keyed by block start address; node data has 'block': BasicBlock.
    Edges have 'kind': 'true' | 'false' | 'jmp' | 'fall' | 'call'.
    """
    insns = disassemble(cs, data[:max_bytes], base_addr)
    if not insns:
        return nx.DiGraph()

    addr_set  = {i.address for i in insns}
    insn_map  = {i.address: i for i in insns}

    # ── Step 1: find block leaders ────────────────────────────────────────────
    leaders: set[int] = {base_addr}

    for insn in insns:
        fall = insn.next_address
        if insn.is_jump or insn.is_ret:
            if fall in addr_set:
                leaders.add(fall)
            if insn.jump_target and insn.jump_target in addr_set:
                leaders.add(insn.jump_target)
        # calls: the instruction after the call starts a new block
        elif insn.is_call:
            if fall in addr_set:
                leaders.add(fall)

    leaders_sorted = sorted(leaders)

    # ── Step 2: build BasicBlocks ─────────────────────────────────────────────
    blocks: dict[int, BasicBlock] = {}

    for idx, leader in enumerate(leaders_sorted):
        next_leader = leaders_sorted[idx + 1] if idx + 1 < len(leaders_sorted) else None
        block_insns: list[Instruction] = []
        addr = leader

        while addr in insn_map:
            insn = insn_map[addr]
            block_insns.append(insn)
            if insn.is_jump or insn.is_ret:
                break
            addr = insn.next_address
            if next_leader is not None and addr >= next_leader:
                break

        if block_insns:
            last = block_insns[-1]
            blocks[leader] = BasicBlock(
                start_addr=leader,
                end_addr=last.next_address,
                instructions=block_insns,
            )

    # ── Step 3: build edges ───────────────────────────────────────────────────
    G: nx.DiGraph = nx.DiGraph()
    for addr, block in blocks.items():
        G.add_node(addr, block=block)

    for addr, block in blocks.items():
        last = block.last
        if last is None:
            continue

        fall = last.next_address

        if last.is_ret:
            continue

        if last.is_jump:
            if last.mnemonic == "jmp":
                # unconditional
                if last.jump_target and last.jump_target in blocks:
                    G.add_edge(addr, last.jump_target, kind="jmp")
            else:
                # conditional: true = target, false = fallthrough
                if last.jump_target and last.jump_target in blocks:
                    G.add_edge(addr, last.jump_target, kind="true")
                if fall in blocks:
                    G.add_edge(addr, fall, kind="false")
        else:
            if fall in blocks:
                G.add_edge(addr, fall, kind="fall")

    return G
