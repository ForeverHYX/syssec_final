from __future__ import annotations

import struct
import zipfile
from pathlib import Path


def uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def build_dex_fixture(
    extra_strings: list[str] | None = None,
    class_descriptors: list[str] | None = None,
    method_names: list[str] | None = None,
    code_units: list[int] | None = None,
) -> bytes:
    extra_strings = extra_strings or []
    class_descriptors = class_descriptors or ["Lcom/example/App;"]
    method_names = method_names or ["<clinit>", "check"]
    code_units = code_units or []

    strings = _dedupe(
        [
            "V",
            *class_descriptors,
            *method_names,
            *extra_strings,
        ]
    )
    string_index = {value: index for index, value in enumerate(strings)}

    types = _dedupe(["V", *class_descriptors])
    type_index = {value: index for index, value in enumerate(types)}

    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(types)
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8 * len(method_names)
    data_off = class_defs_off + 32

    data = bytearray()
    string_offsets: list[int] = []
    for value in strings:
        string_offsets.append(data_off + len(data))
        raw = value.encode("utf-8")
        data.extend(uleb128(len(value)))
        data.extend(raw)
        data.append(0)

    if len(data) % 4:
        data.extend(b"\x00" * (4 - len(data) % 4))

    code_off = data_off + len(data)
    insns = code_units
    data.extend(struct.pack("<HHHHII", 4, 1, 2, 0, 0, len(insns)))
    data.extend(b"".join(struct.pack("<H", unit) for unit in insns))
    if len(insns) % 2:
        data.extend(b"\x00\x00")

    class_data_off = data_off + len(data)
    class_data = bytearray()
    class_data.extend(uleb128(0))
    class_data.extend(uleb128(0))
    class_data.extend(uleb128(1))
    class_data.extend(uleb128(0))
    class_data.extend(uleb128(0))
    class_data.extend(uleb128(0x10008))
    class_data.extend(uleb128(code_off))
    data.extend(class_data)

    file_size = data_off + len(data)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x38, len(strings))
    struct.pack_into("<I", header, 0x3C, string_ids_off)
    struct.pack_into("<I", header, 0x40, len(types))
    struct.pack_into("<I", header, 0x44, type_ids_off)
    struct.pack_into("<I", header, 0x48, 1)
    struct.pack_into("<I", header, 0x4C, proto_ids_off)
    struct.pack_into("<I", header, 0x58, len(method_names))
    struct.pack_into("<I", header, 0x5C, method_ids_off)
    struct.pack_into("<I", header, 0x60, 1)
    struct.pack_into("<I", header, 0x64, class_defs_off)
    struct.pack_into("<I", header, 0x68, len(data))
    struct.pack_into("<I", header, 0x6C, data_off)

    string_ids = b"".join(struct.pack("<I", offset) for offset in string_offsets)
    type_ids = b"".join(struct.pack("<I", string_index[value]) for value in types)
    proto_ids = struct.pack("<III", string_index["V"], type_index["V"], 0)
    method_ids = b"".join(
        struct.pack("<HHI", type_index[class_descriptors[0]], 0, string_index[name])
        for name in method_names
    )
    class_defs = struct.pack(
        "<IIIIIIII",
        type_index[class_descriptors[0]],
        0x1,
        0xFFFFFFFF,
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
    )
    return bytes(header) + string_ids + type_ids + proto_ids + method_ids + class_defs + bytes(data)


def const_string_instruction(string_index: int) -> list[int]:
    return [0x001A, string_index]


def invoke_static_instruction(method_index: int) -> list[int]:
    return [0x0071, method_index, 0, 0]


def build_apk(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as apk:
        for name, data in files.items():
            apk.writestr(name, data)
    return path


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result

