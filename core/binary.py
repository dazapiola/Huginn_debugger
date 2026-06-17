"""Binary parsing via LIEF — supports ELF (Linux) and PE (Windows)."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import lief


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    file_offset: int
    size: int
    flags: str          # e.g. "rx", "rw", "r"
    _content: bytes = field(default=b"", repr=False)

    @property
    def content(self) -> bytes:
        return self._content

    def contains(self, addr: int) -> bool:
        return self.virtual_address <= addr < self.virtual_address + self.size


@dataclass
class SegmentInfo:
    kind: str           # "LOAD", "DYNAMIC", etc.
    virtual_address: int
    file_offset: int
    physical_size: int  # bytes on disk
    virtual_size: int   # bytes in memory
    flags: str          # "r", "rx", "rw", "rwx"
    _content: bytes = field(default=b"", repr=False)

    @property
    def content(self) -> bytes:
        return self._content

    def contains(self, addr: int) -> bool:
        return self.virtual_address <= addr < self.virtual_address + self.virtual_size


@dataclass
class SymbolInfo:
    name: str
    address: int
    size: int = 0


@dataclass
class BinaryInfo:
    path: str
    arch: str           # "x86_64", "x86", "arm64", "arm"
    bits: int           # 32 or 64
    fmt: str            # "ELF", "PE", "Mach-O"
    entry_point: int
    base_address: int
    sections: list[SectionInfo] = field(default_factory=list)
    segments: list[SegmentInfo] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)
    raw: bytes = field(default=b"", repr=False)

    @property
    def name(self) -> str:
        return Path(self.path).name

    def section_at(self, addr: int) -> SectionInfo | None:
        for s in self.sections:
            if s.contains(addr):
                return s
        return None

    def segment_at(self, addr: int) -> SegmentInfo | None:
        for s in self.segments:
            if s.contains(addr):
                return s
        return None


def load(path: str) -> BinaryInfo:
    """Parse a binary with LIEF and return a BinaryInfo."""
    binary = lief.parse(path)
    if binary is None:
        raise ValueError(f"Cannot parse binary: {path}")

    with open(path, "rb") as f:
        raw = f.read()

    fmt = _detect_format(binary)
    arch, bits = _detect_arch(binary, fmt)
    base = _detect_base(binary, fmt)

    sections = _parse_sections(binary, fmt)
    segments = _parse_segments(binary, fmt)
    symbols = _parse_symbols(binary)

    return BinaryInfo(
        path=path,
        arch=arch,
        bits=bits,
        fmt=fmt,
        entry_point=binary.entrypoint,  # type: ignore[union-attr]
        base_address=base,
        sections=sections,
        segments=segments,
        symbols=symbols,
        raw=raw,
    )


# ── internal helpers ──────────────────────────────────────────────────────────

def _detect_format(binary) -> str:
    fmt = str(binary.format)
    if "ELF" in fmt:   return "ELF"
    if "PE" in fmt:    return "PE"
    if "MACHO" in fmt: return "Mach-O"
    return "unknown"


def _detect_arch(binary, _fmt: str) -> tuple[str, int]:
    try:
        mtype = str(binary.header.machine_type)
        if "X86_64" in mtype or "AMD64" in mtype:  return ("x86_64", 64)
        if "I386" in mtype or "I686" in mtype:     return ("x86",    32)
        if "AARCH64" in mtype or "ARM64" in mtype: return ("arm64",  64)
        if "ARM" in mtype:                          return ("arm",    32)
    except AttributeError:
        pass
    return ("unknown", 64)


def _detect_base(binary, fmt: str) -> int:
    """Return the load base — lowest LOAD segment virtual address."""
    try:
        if fmt == "ELF":
            load_segs = [s for s in binary.segments if "LOAD" in str(s.type)]
            if load_segs:
                return min(s.virtual_address for s in load_segs)
        elif fmt == "PE":
            return binary.optional_header.imagebase
    except AttributeError:
        pass
    return 0


def _elf_section_flags(flags_int: int) -> str:
    # SHF_WRITE=0x1, SHF_ALLOC=0x2, SHF_EXECINSTR=0x4
    result = "r"
    if flags_int & 0x4: result += "x"
    if flags_int & 0x1: result += "w"
    return result


def _elf_segment_flags(seg) -> str:
    FLAGS = lief.ELF.Segment.FLAGS
    result = ""
    if FLAGS.R in seg.flags: result += "r"
    if FLAGS.W in seg.flags: result += "w"
    if FLAGS.X in seg.flags: result += "x"
    return result or "r"


def _pe_section_flags(sec) -> str:
    try:
        SC = lief.PE.Section.CHARACTERISTICS
        result = ""
        if sc_has(sec, SC.MEM_READ):    result += "r"
        if sc_has(sec, SC.MEM_WRITE):   result += "w"
        if sc_has(sec, SC.MEM_EXECUTE): result += "x"
        return result or "r"
    except Exception:
        return "r"


def sc_has(sec, flag) -> bool:
    try:
        return sec.has_characteristic(flag)
    except Exception:
        return False


def _parse_sections(binary, fmt: str) -> list[SectionInfo]:
    sections = []
    for sec in binary.sections:
        try:
            content = bytes(sec.content)
        except Exception:
            content = b""

        if fmt == "ELF":
            flags = _elf_section_flags(int(sec.flags))
            offset = getattr(sec, "offset", 0)
        elif fmt == "PE":
            flags = _pe_section_flags(sec)
            offset = getattr(sec, "pointerto_raw_data", 0)
        else:
            flags = "r"
            offset = 0

        if sec.virtual_address == 0 and sec.size == 0:
            continue

        sections.append(SectionInfo(
            name=sec.name,
            virtual_address=sec.virtual_address,
            file_offset=offset,
            size=sec.size,
            flags=flags,
            _content=content,
        ))
    return sections


def _parse_segments(binary, fmt: str) -> list[SegmentInfo]:
    segments = []
    if fmt not in ("ELF",):
        return segments
    for seg in binary.segments:
        try:
            content = bytes(seg.content)
        except Exception:
            content = b""
        segments.append(SegmentInfo(
            kind=str(seg.type).replace("TYPE.", ""),
            virtual_address=seg.virtual_address,
            file_offset=seg.file_offset,
            physical_size=seg.physical_size,
            virtual_size=seg.virtual_size,
            flags=_elf_segment_flags(seg),
            _content=content,
        ))
    return segments


def _parse_symbols(binary) -> list[SymbolInfo]:
    symbols = []
    try:
        for sym in binary.symbols:
            if sym.value and sym.name:
                symbols.append(SymbolInfo(
                    name=sym.name,
                    address=sym.value,
                    size=getattr(sym, "size", 0),
                ))
    except AttributeError:
        pass
    return symbols
