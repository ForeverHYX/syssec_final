import hashlib
import zlib

from hardeninspector.dex import DexFile

from .fixtures import (
    build_dex_fixture,
    const_string_instruction,
    goto_instruction,
    if_eq_instruction,
    invoke_static_instruction,
    packed_switch_instruction,
)


def test_dex_parser_extracts_strings_types_methods_and_code_evidence():
    dex = build_dex_fixture(
        extra_strings=["ro.kernel.qemu", "DexClassLoader"],
        class_descriptors=["Lcom/a/A;"],
        method_names=["<clinit>", "target"],
        code_units=[
            *const_string_instruction(4),
            *invoke_static_instruction(1),
        ],
    )

    parsed = DexFile.parse("classes.dex", dex)

    assert "ro.kernel.qemu" in parsed.strings
    assert "Lcom/a/A;" in parsed.type_descriptors
    assert [method.name for method in parsed.methods] == ["<clinit>", "target"]
    assert parsed.const_strings == ["ro.kernel.qemu"]
    assert parsed.invoked_methods[0].name == "target"
    assert parsed.opcode_counts[0x1A] == 1
    assert parsed.opcode_counts[0x71] == 1
    assert parsed.opcode_profile.instruction_count == 2
    assert parsed.opcode_profile.const_string_count == 1
    assert parsed.opcode_profile.invoke_count == 1
    assert parsed.code_methods[0].name == "<clinit>"


def test_dex_parser_returns_empty_evidence_for_invalid_dex():
    parsed = DexFile.parse("bad.dex", b"not a dex")

    assert parsed.strings == []
    assert parsed.type_descriptors == []
    assert parsed.methods == []
    assert parsed.parse_errors


def test_synthetic_dex_has_standard_signature_and_checksum():
    dex = build_dex_fixture(
        extra_strings=["DexClassLoader"],
        class_descriptors=["Lcom/example/App;"],
    )

    assert dex[12:32] == hashlib.sha1(dex[32:]).digest()
    assert int.from_bytes(dex[8:12], "little") == zlib.adler32(dex[12:]) & 0xFFFFFFFF


def test_dex_opcode_profile_counts_control_flow_instructions():
    dex = build_dex_fixture(
        class_descriptors=["Lcom/example/Flow;"],
        method_names=["<clinit>", "dispatch"],
        code_units=[
            *if_eq_instruction(),
            *if_eq_instruction(),
            *if_eq_instruction(),
            *goto_instruction(),
            *goto_instruction(),
            *packed_switch_instruction(),
            *const_string_instruction(2),
            *invoke_static_instruction(1),
        ],
    )

    parsed = DexFile.parse("classes.dex", dex)
    profile = parsed.opcode_profile

    assert profile.instruction_count == 8
    assert profile.conditional_branch_count == 3
    assert profile.goto_count == 2
    assert profile.switch_count == 1
    assert profile.control_flow_count == 6
    assert profile.control_flow_density == 0.75
