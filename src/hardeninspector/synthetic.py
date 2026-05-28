"""Deterministic synthetic APK builders used for tests and datasets."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import struct
import zlib
import zipfile
from pathlib import Path


DETERMINISTIC_ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class SyntheticApkSpec:
    manifest_strings: list[str]
    class_descriptors: list[str]
    method_names: list[str] = field(default_factory=lambda: ["<clinit>", "check"])
    dex_strings: list[str] = field(default_factory=list)
    native_libraries: dict[str, bytes] = field(default_factory=dict)
    assets: dict[str, bytes] = field(default_factory=dict)
    const_string_values: list[str] = field(default_factory=list)
    code_units: list[int] | None = None


def build_synthetic_apk(path: Path, spec: SyntheticApkSpec) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    dex = build_dex(
        extra_strings=spec.dex_strings,
        class_descriptors=spec.class_descriptors,
        method_names=spec.method_names,
        code_units=spec.code_units,
        const_string_values=spec.const_string_values,
    )
    files: dict[str, bytes] = {
        "AndroidManifest.xml": build_axml_string_pool(spec.manifest_strings),
        "classes.dex": dex,
    }
    files.update(spec.native_libraries)
    files.update(spec.assets)
    with zipfile.ZipFile(path, "w") as apk:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=DETERMINISTIC_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            apk.writestr(info, data)
    return path


def build_elf_shared_object(symbol_names: list[str]) -> bytes:
    """Build a tiny deterministic ELF64 shared object with a `.dynsym` table."""

    symbols = _dedupe(symbol_names)
    dynstr_offsets: dict[str, int] = {}
    dynstr = bytearray(b"\x00")
    for name in symbols:
        dynstr_offsets[name] = len(dynstr)
        dynstr.extend(name.encode("utf-8"))
        dynstr.append(0)

    dynsym = bytearray(b"\x00" * 24)
    for name in symbols:
        st_name = dynstr_offsets[name]
        st_info = (1 << 4) | 2  # STB_GLOBAL + STT_FUNC
        dynsym.extend(struct.pack("<IBBHQQ", st_name, st_info, 0, 0, 0, 0))

    shstrtab = b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    sh_name_dynstr = shstrtab.index(b".dynstr")
    sh_name_dynsym = shstrtab.index(b".dynsym")
    sh_name_shstrtab = shstrtab.index(b".shstrtab")

    elf_header_size = 64
    dynstr_off = elf_header_size
    dynsym_off = _align(dynstr_off + len(dynstr), 8)
    shstrtab_off = _align(dynsym_off + len(dynsym), 1)
    shoff = _align(shstrtab_off + len(shstrtab), 8)
    file_size = shoff + 4 * 64

    data = bytearray(b"\x00" * file_size)
    data[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    data[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    data[shstrtab_off : shstrtab_off + len(shstrtab)] = shstrtab

    data[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,  # ET_DYN
        183,  # EM_AARCH64
        1,
        0,
        0,
        shoff,
        0,
        elf_header_size,
        0,
        0,
        64,
        4,
        3,
    )

    section_headers = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (sh_name_dynstr, 3, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
        (sh_name_dynsym, 11, 0, 0, dynsym_off, len(dynsym), 1, 1, 8, 24),
        (sh_name_shstrtab, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0),
    ]
    for index, header in enumerate(section_headers):
        struct.pack_into("<IIQQQQIIQQ", data, shoff + index * 64, *header)

    return bytes(data)


def build_axml_string_pool(strings: list[str]) -> bytes:
    encoded = []
    offsets = []
    cursor = 0
    for value in strings:
        raw = value.encode("utf-8")
        item = bytes([len(value), len(raw)]) + raw + b"\x00"
        offsets.append(cursor)
        encoded.append(item)
        cursor += len(item)

    strings_data = b"".join(encoded)
    header_size = 28
    chunk_size = header_size + len(offsets) * 4 + len(strings_data)
    strings_start = header_size + len(offsets) * 4
    return (
        struct.pack("<HHI", 0x0001, header_size, chunk_size)
        + struct.pack("<IIIII", len(strings), 0, 0x00000100, strings_start, 0)
        + b"".join(struct.pack("<I", offset) for offset in offsets)
        + strings_data
    )


def build_dex(
    extra_strings: list[str] | None = None,
    class_descriptors: list[str] | None = None,
    method_names: list[str] | None = None,
    code_units: list[int] | None = None,
    const_string_values: list[str] | None = None,
) -> bytes:
    extra_strings = extra_strings or []
    class_descriptors = class_descriptors or ["Lcom/example/App;"]
    method_names = method_names or ["<clinit>", "check"]
    const_string_values = const_string_values or []

    strings = _dedupe(
        [
            "V",
            *class_descriptors,
            *method_names,
            *extra_strings,
            *const_string_values,
        ]
    )
    string_index = {value: index for index, value in enumerate(strings)}
    if code_units is None:
        code_units = []
        for value in const_string_values:
            code_units.extend(const_string_instruction(string_index[value]))

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
    data.extend(struct.pack("<HHHHII", 4, 1, 2, 0, 0, len(code_units)))
    data.extend(b"".join(struct.pack("<H", unit) for unit in code_units))
    if len(code_units) % 2:
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

    if len(data) % 4:
        data.extend(b"\x00" * (4 - len(data) % 4))

    map_off = data_off + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(types), type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, len(method_names), method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x1000, 1, map_off),
        (0x2000, 1, class_data_off),
        (0x2001, 1, code_off),
        (0x2002, len(strings), string_offsets[0]),
    ]
    data.extend(struct.pack("<I", len(map_items)))
    for item_type, item_size, item_off in map_items:
        data.extend(struct.pack("<HHII", item_type, 0, item_size, item_off))

    file_size = data_off + len(data)

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, file_size)
    struct.pack_into("<I", header, 0x24, header_size)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    struct.pack_into("<I", header, 0x34, map_off)
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
    dex = bytearray(bytes(header) + string_ids + type_ids + proto_ids + method_ids + class_defs + bytes(data))
    dex[12:32] = hashlib.sha1(dex[32:]).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]) & 0xFFFFFFFF)
    return bytes(dex)


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


def const_string_instruction(string_index: int) -> list[int]:
    return [0x001A, string_index]


def invoke_static_instruction(method_index: int) -> list[int]:
    return [0x0071, method_index, 0]


def if_eq_instruction(offset: int = 0) -> list[int]:
    return [0x0032, offset & 0xFFFF]


def goto_instruction(offset: int = 0) -> list[int]:
    return [0x0028 | ((offset & 0xFF) << 8)]


def packed_switch_instruction(payload_offset: int = 0) -> list[int]:
    return [0x002B, payload_offset & 0xFFFF, (payload_offset >> 16) & 0xFFFF]


def _align(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
