"""Disassembly engine wrapper over Capstone."""
from __future__ import annotations
from dataclasses import dataclass
import capstone
import capstone.x86


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    # Capstone group flags (populated when cs.detail=True)
    is_jump: bool = False
    is_call: bool = False
    is_ret: bool = False
    is_branch_relative: bool = False
    jump_target: int | None = None   # resolved absolute addr for direct branches

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    @property
    def hex_bytes(self) -> str:
        return self.raw.hex()

    @property
    def next_address(self) -> int:
        return self.address + self.size


_ARCH_MAP: dict[tuple[str, int], tuple[int, int]] = {
    ("x86_64", 64): (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
    ("x86",    32): (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
    ("arm64",  64): (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    ("arm",    32): (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
}


def create_disassembler(arch: str, bits: int) -> capstone.Cs:
    key = (arch, bits)
    if key not in _ARCH_MAP:
        raise ValueError(f"Unsupported arch: {arch}/{bits}bit")
    cs = capstone.Cs(*_ARCH_MAP[key])
    cs.detail = True
    return cs


def disassemble(cs: capstone.Cs, data: bytes, base_addr: int,
                max_insns: int = 0) -> list[Instruction]:
    result = []
    for i in cs.disasm(data, base_addr, count=max_insns or 0):
        result.append(_build(cs, i))
    return result


def disasm_one(cs: capstone.Cs, data: bytes, addr: int) -> Instruction | None:
    for i in cs.disasm(data, addr, count=1):
        return _build(cs, i)
    return None


def _build(_cs: capstone.Cs, i) -> Instruction:
    is_jump = capstone.CS_GRP_JUMP in i.groups
    is_call = capstone.CS_GRP_CALL in i.groups
    is_ret  = capstone.CS_GRP_RET  in i.groups
    is_rel  = capstone.CS_GRP_BRANCH_RELATIVE in i.groups

    target = None
    if (is_jump or is_call) and is_rel and i.operands:
        op = i.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            target = op.imm

    return Instruction(
        address=i.address,
        size=i.size,
        mnemonic=i.mnemonic,
        op_str=i.op_str,
        raw=bytes(i.bytes),
        is_jump=is_jump,
        is_call=is_call,
        is_ret=is_ret,
        is_branch_relative=is_rel,
        jump_target=target,
    )
