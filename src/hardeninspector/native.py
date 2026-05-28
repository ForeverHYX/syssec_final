"""Lightweight ELF evidence extraction for native libraries."""

from __future__ import annotations

from dataclasses import dataclass
import struct


SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11

SYMBOL_TYPES = {
    0: "notype",
    1: "object",
    2: "function",
    3: "section",
    4: "file",
    5: "common",
    6: "tls",
}

SYMBOL_BINDINGS = {
    0: "local",
    1: "global",
    2: "weak",
}


@dataclass(frozen=True)
class ElfSymbol:
    name: str
    table: str
    binding: str
    symbol_type: str


@dataclass(frozen=True)
class _Section:
    name: str
    section_type: int
    offset: int
    size: int
    link: int
    entsize: int


def extract_elf_symbols(data: bytes) -> list[ElfSymbol]:
    """Extract symbol names from ELF symbol tables.

    The detector only needs symbol-level evidence. This intentionally avoids
    full ELF loading, relocation processing, or disassembly.
    """

    try:
        return _extract_elf_symbols_or_raise(data)
    except (IndexError, ValueError, struct.error):
        return []


def _extract_elf_symbols_or_raise(data: bytes) -> list[ElfSymbol]:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return []
    elf_class = data[4]
    endian_id = data[5]
    if elf_class not in (1, 2) or endian_id not in (1, 2):
        return []
    endian = "<" if endian_id == 1 else ">"

    if elf_class == 2:
        if len(data) < 0x40:
            return []
        shoff = _unpack_from(endian + "Q", data, 0x28)
        shentsize = _unpack_from(endian + "H", data, 0x3A)
        shnum = _unpack_from(endian + "H", data, 0x3C)
        shstrndx = _unpack_from(endian + "H", data, 0x3E)
        sections = _read_elf64_sections(data, endian, shoff, shentsize, shnum, shstrndx)
        return _read_symbols(data, endian, 64, sections)

    shoff = _unpack_from(endian + "I", data, 0x20)
    shentsize = _unpack_from(endian + "H", data, 0x2E)
    shnum = _unpack_from(endian + "H", data, 0x30)
    shstrndx = _unpack_from(endian + "H", data, 0x32)
    sections = _read_elf32_sections(data, endian, shoff, shentsize, shnum, shstrndx)
    return _read_symbols(data, endian, 32, sections)


def _read_elf64_sections(
    data: bytes,
    endian: str,
    shoff: int,
    shentsize: int,
    shnum: int,
    shstrndx: int,
) -> list[_Section]:
    raw_sections: list[tuple[int, int, int, int, int, int]] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + 64 > len(data):
            break
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = struct.unpack_from(
            endian + "IIQQQQIIQQ", data, offset
        )
        raw_sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    return _name_sections(data, raw_sections, shstrndx)


def _read_elf32_sections(
    data: bytes,
    endian: str,
    shoff: int,
    shentsize: int,
    shnum: int,
    shstrndx: int,
) -> list[_Section]:
    raw_sections: list[tuple[int, int, int, int, int, int]] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + 40 > len(data):
            break
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = struct.unpack_from(
            endian + "IIIIIIIIII", data, offset
        )
        raw_sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    return _name_sections(data, raw_sections, shstrndx)


def _name_sections(
    data: bytes,
    raw_sections: list[tuple[int, int, int, int, int, int]],
    shstrndx: int,
) -> list[_Section]:
    if shstrndx >= len(raw_sections):
        section_names = b""
    else:
        _name, _type, offset, size, _link, _entsize = raw_sections[shstrndx]
        section_names = _slice(data, offset, size)
    sections: list[_Section] = []
    for name_offset, section_type, offset, size, link, entsize in raw_sections:
        sections.append(
            _Section(
                name=_read_c_string(section_names, name_offset),
                section_type=section_type,
                offset=offset,
                size=size,
                link=link,
                entsize=entsize,
            )
        )
    return sections


def _read_symbols(data: bytes, endian: str, bits: int, sections: list[_Section]) -> list[ElfSymbol]:
    symbols: list[ElfSymbol] = []
    for section in sections:
        if section.section_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section.link >= len(sections):
            continue
        string_section = sections[section.link]
        if string_section.section_type != SHT_STRTAB:
            continue
        string_table = _slice(data, string_section.offset, string_section.size)
        entry_size = section.entsize or (24 if bits == 64 else 16)
        count = section.size // entry_size if entry_size else 0
        for index in range(count):
            offset = section.offset + index * entry_size
            if bits == 64:
                if offset + 24 > len(data):
                    break
                name_offset, info, _other, _shndx, _value, _size = struct.unpack_from(endian + "IBBHQQ", data, offset)
            else:
                if offset + 16 > len(data):
                    break
                name_offset, _value, _size, info, _other, _shndx = struct.unpack_from(endian + "IIIBBH", data, offset)
            name = _read_c_string(string_table, name_offset)
            if not name:
                continue
            symbols.append(
                ElfSymbol(
                    name=name,
                    table=section.name or (".dynsym" if section.section_type == SHT_DYNSYM else ".symtab"),
                    binding=SYMBOL_BINDINGS.get(info >> 4, f"binding:{info >> 4}"),
                    symbol_type=SYMBOL_TYPES.get(info & 0x0F, f"type:{info & 0x0F}"),
                )
            )
    return _dedupe_symbols(symbols)


def _slice(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        return b""
    return data[offset : offset + size]


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _unpack_from(fmt: str, data: bytes, offset: int) -> int:
    return struct.unpack_from(fmt, data, offset)[0]


def _dedupe_symbols(symbols: list[ElfSymbol]) -> list[ElfSymbol]:
    result: list[ElfSymbol] = []
    seen: set[tuple[str, str, str, str]] = set()
    for symbol in symbols:
        key = (symbol.name, symbol.table, symbol.binding, symbol.symbol_type)
        if key not in seen:
            seen.add(key)
            result.append(symbol)
    return result
