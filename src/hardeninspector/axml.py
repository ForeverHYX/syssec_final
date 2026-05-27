"""Lightweight Android binary XML string-pool extraction."""

from __future__ import annotations

import struct


RES_STRING_POOL_TYPE = 0x0001
UTF8_FLAG = 0x00000100


def extract_axml_strings(data: bytes) -> list[str]:
    """Extract strings from Android binary XML string pool chunks.

    This intentionally does not fully decode Android XML. Detector rules only
    need manifest strings such as application class names, permissions, and
    suspicious constants.
    """

    strings: list[str] = []
    for offset in _iter_chunk_offsets(data):
        chunk_strings = _parse_string_pool_at(data, offset)
        if chunk_strings:
            strings.extend(chunk_strings)
    return strings


def _iter_chunk_offsets(data: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while cursor + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, cursor)
        if chunk_type == RES_STRING_POOL_TYPE:
            offsets.append(cursor)
        if header_size < 8 or chunk_size < header_size:
            cursor += 4
            continue
        cursor += chunk_size

    if not offsets and len(data) >= 8:
        chunk_type, _, _ = struct.unpack_from("<HHI", data, 0)
        if chunk_type == RES_STRING_POOL_TYPE:
            offsets.append(0)
    return offsets


def _parse_string_pool_at(data: bytes, base: int) -> list[str]:
    if base + 28 > len(data):
        return []
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, base)
    if chunk_type != RES_STRING_POOL_TYPE or header_size < 28:
        return []
    if base + chunk_size > len(data):
        return []

    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, base + 8
    )
    offsets_start = base + header_size
    strings_base = base + strings_start
    is_utf8 = bool(flags & UTF8_FLAG)

    result: list[str] = []
    for index in range(string_count):
        offset_pos = offsets_start + index * 4
        if offset_pos + 4 > len(data):
            break
        relative_offset = struct.unpack_from("<I", data, offset_pos)[0]
        string_offset = strings_base + relative_offset
        if string_offset >= len(data):
            continue
        value = _read_utf8_string(data, string_offset) if is_utf8 else _read_utf16_string(data, string_offset)
        if value is not None:
            result.append(value)
    return result


def _read_length8(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    if first & 0x80:
        if offset + 1 >= len(data):
            return None
        return ((first & 0x7F) << 8) | data[offset + 1], 2
    return first, 1


def _read_utf8_string(data: bytes, offset: int) -> str | None:
    utf16_len = _read_length8(data, offset)
    if utf16_len is None:
        return None
    byte_len = _read_length8(data, offset + utf16_len[1])
    if byte_len is None:
        return None
    start = offset + utf16_len[1] + byte_len[1]
    end = start + byte_len[0]
    if end > len(data):
        return None
    return data[start:end].decode("utf-8", errors="replace")


def _read_utf16_length(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 2 > len(data):
        return None
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        if offset + 4 > len(data):
            return None
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7FFF) << 16) | second, 4
    return first, 2


def _read_utf16_string(data: bytes, offset: int) -> str | None:
    length = _read_utf16_length(data, offset)
    if length is None:
        return None
    start = offset + length[1]
    end = start + length[0] * 2
    if end > len(data):
        return None
    return data[start:end].decode("utf-16le", errors="replace")

