"""Small DEX parser for static hardening evidence."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import struct


@dataclass(frozen=True)
class MethodReference:
    index: int
    class_descriptor: str
    name: str


@dataclass(frozen=True)
class CodeMethod:
    method: MethodReference
    code_offset: int
    opcode_counts: Counter[int]
    const_strings: list[str]
    invoked_methods: list[MethodReference]

    @property
    def name(self) -> str:
        return self.method.name


@dataclass
class DexFile:
    name: str
    strings: list[str] = field(default_factory=list)
    type_descriptors: list[str] = field(default_factory=list)
    methods: list[MethodReference] = field(default_factory=list)
    code_methods: list[CodeMethod] = field(default_factory=list)
    opcode_counts: Counter[int] = field(default_factory=Counter)
    const_strings: list[str] = field(default_factory=list)
    invoked_methods: list[MethodReference] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, name: str, data: bytes) -> "DexFile":
        parser = _DexParser(name, data)
        return parser.parse()


class _DexParser:
    def __init__(self, name: str, data: bytes) -> None:
        self.result = DexFile(name=name)
        self.data = data

    def parse(self) -> DexFile:
        try:
            self._parse_or_raise()
        except Exception as exc:  # noqa: BLE001 - parser must be best-effort
            self.result.parse_errors.append(str(exc))
        return self.result

    def _parse_or_raise(self) -> None:
        if len(self.data) < 0x70 or not self.data.startswith(b"dex\n"):
            raise ValueError("not a DEX file")

        string_ids_size = self._u32(0x38)
        string_ids_off = self._u32(0x3C)
        type_ids_size = self._u32(0x40)
        type_ids_off = self._u32(0x44)
        method_ids_size = self._u32(0x58)
        method_ids_off = self._u32(0x5C)
        class_defs_size = self._u32(0x60)
        class_defs_off = self._u32(0x64)

        self.result.strings = self._parse_strings(string_ids_size, string_ids_off)
        self.result.type_descriptors = self._parse_types(type_ids_size, type_ids_off)
        self.result.methods = self._parse_methods(method_ids_size, method_ids_off)
        self._parse_class_defs(class_defs_size, class_defs_off)

    def _parse_strings(self, size: int, offset: int) -> list[str]:
        strings: list[str] = []
        for index in range(size):
            string_data_off = self._u32(offset + index * 4)
            _utf16_size, cursor = self._read_uleb128(string_data_off)
            end = self.data.find(b"\x00", cursor)
            if end == -1:
                end = len(self.data)
            strings.append(self.data[cursor:end].decode("utf-8", errors="replace"))
        return strings

    def _parse_types(self, size: int, offset: int) -> list[str]:
        descriptors: list[str] = []
        for index in range(size):
            descriptor_idx = self._u32(offset + index * 4)
            descriptors.append(self._string_at(descriptor_idx))
        return descriptors

    def _parse_methods(self, size: int, offset: int) -> list[MethodReference]:
        methods: list[MethodReference] = []
        for index in range(size):
            class_idx, _proto_idx, name_idx = struct.unpack_from("<HHI", self.data, offset + index * 8)
            methods.append(
                MethodReference(
                    index=index,
                    class_descriptor=self._type_at(class_idx),
                    name=self._string_at(name_idx),
                )
            )
        return methods

    def _parse_class_defs(self, size: int, offset: int) -> None:
        for index in range(size):
            class_def_off = offset + index * 32
            if class_def_off + 32 > len(self.data):
                return
            class_data_off = self._u32(class_def_off + 24)
            if class_data_off:
                self._parse_class_data(class_data_off)

    def _parse_class_data(self, offset: int) -> None:
        static_fields_size, offset = self._read_uleb128(offset)
        instance_fields_size, offset = self._read_uleb128(offset)
        direct_methods_size, offset = self._read_uleb128(offset)
        virtual_methods_size, offset = self._read_uleb128(offset)

        for _ in range(static_fields_size + instance_fields_size):
            _field_idx_diff, offset = self._read_uleb128(offset)
            _access_flags, offset = self._read_uleb128(offset)

        method_idx = 0
        for _ in range(direct_methods_size + virtual_methods_size):
            method_idx_diff, offset = self._read_uleb128(offset)
            _access_flags, offset = self._read_uleb128(offset)
            code_off, offset = self._read_uleb128(offset)
            method_idx += method_idx_diff
            method = self._method_at(method_idx)
            if method is not None and code_off:
                self._parse_code_item(method, code_off)

    def _parse_code_item(self, method: MethodReference, offset: int) -> None:
        if offset + 16 > len(self.data):
            return
        insns_size = self._u32(offset + 12)
        insns_off = offset + 16
        code_units: list[int] = []
        for index in range(insns_size):
            unit_off = insns_off + index * 2
            if unit_off + 2 > len(self.data):
                break
            code_units.append(struct.unpack_from("<H", self.data, unit_off)[0])

        opcode_counts: Counter[int] = Counter()
        const_strings: list[str] = []
        invoked_methods: list[MethodReference] = []
        cursor = 0
        while cursor < len(code_units):
            opcode = code_units[cursor] & 0xFF
            opcode_counts[opcode] += 1
            if opcode == 0x1A and cursor + 1 < len(code_units):
                const_strings.append(self._string_at(code_units[cursor + 1]))
                cursor += 2
                continue
            if opcode == 0x1B and cursor + 2 < len(code_units):
                string_idx = code_units[cursor + 1] | (code_units[cursor + 2] << 16)
                const_strings.append(self._string_at(string_idx))
                cursor += 3
                continue
            if 0x6E <= opcode <= 0x72 and cursor + 1 < len(code_units):
                invoked = self._method_at(code_units[cursor + 1])
                if invoked is not None:
                    invoked_methods.append(invoked)
                cursor += 3
                continue
            cursor += 1

        self.result.code_methods.append(
            CodeMethod(
                method=method,
                code_offset=offset,
                opcode_counts=opcode_counts,
                const_strings=const_strings,
                invoked_methods=invoked_methods,
            )
        )
        self.result.opcode_counts.update(opcode_counts)
        self.result.const_strings.extend(const_strings)
        self.result.invoked_methods.extend(invoked_methods)

    def _string_at(self, index: int) -> str:
        if 0 <= index < len(self.result.strings):
            return self.result.strings[index]
        return f"<string:{index}>"

    def _type_at(self, index: int) -> str:
        if 0 <= index < len(self.result.type_descriptors):
            return self.result.type_descriptors[index]
        return f"<type:{index}>"

    def _method_at(self, index: int) -> MethodReference | None:
        if 0 <= index < len(self.result.methods):
            return self.result.methods[index]
        return None

    def _u32(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            raise ValueError(f"offset outside DEX: 0x{offset:x}")
        return struct.unpack_from("<I", self.data, offset)[0]

    def _read_uleb128(self, offset: int) -> tuple[int, int]:
        result = 0
        shift = 0
        cursor = offset
        for _ in range(5):
            if cursor >= len(self.data):
                raise ValueError("truncated uleb128")
            byte = self.data[cursor]
            cursor += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result, cursor
            shift += 7
        raise ValueError("uleb128 too long")

