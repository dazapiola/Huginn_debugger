"""Static (file-only) backend — reads from the binary on disk, no process."""
from __future__ import annotations
from .base import DebuggerBackend, ModuleInfo, PageInfo
from core.binary import BinaryInfo, load as load_binary


class StaticBackend(DebuggerBackend):

    def __init__(self) -> None:
        self._binary: BinaryInfo | None = None

    @property
    def binary(self) -> BinaryInfo | None:
        return self._binary

    # ── DebuggerBackend interface ─────────────────────────────────────────────

    def load(self, path: str) -> BinaryInfo:
        self._binary = load_binary(path)
        return self._binary

    def read_memory(self, addr: int, size: int) -> bytes:
        """Map virtual address → bytes using the loaded binary segments/sections."""
        if self._binary is None:
            return b"\x00" * size

        # Prefer segments (they define the actual memory layout)
        for seg in self._binary.segments:
            if seg.kind != "LOAD":
                continue
            if seg.virtual_address <= addr < seg.virtual_address + seg.physical_size:
                offset = addr - seg.virtual_address
                chunk = seg.content[offset:offset + size]
                return chunk.ljust(size, b"\x00")

        # Fallback: sections (useful for PE or ELF without segments)
        for sec in self._binary.sections:
            if sec.virtual_address == 0:
                continue
            if sec.virtual_address <= addr < sec.virtual_address + sec.size:
                offset = addr - sec.virtual_address
                chunk = sec.content[offset:offset + size]
                return chunk.ljust(size, b"\x00")

        return b"\x00" * size

    def get_modules(self) -> list[ModuleInfo]:
        if self._binary is None:
            return []
        return [ModuleInfo(
            name=self._binary.name,
            base=self._binary.base_address,
            size=len(self._binary.raw),
            path=self._binary.path,
        )]

    def get_memory_pages(self) -> list[PageInfo]:
        if self._binary is None:
            return []
        pages = []
        for seg in self._binary.segments:
            if seg.kind == "LOAD" and seg.physical_size > 0:
                pages.append(PageInfo(
                    base=seg.virtual_address,
                    size=seg.physical_size,
                    protection=seg.flags,
                ))
        if not pages:
            for sec in self._binary.sections:
                if sec.virtual_address > 0 and sec.size > 0:
                    pages.append(PageInfo(
                        base=sec.virtual_address,
                        size=sec.size,
                        protection=sec.flags,
                    ))
        return pages
