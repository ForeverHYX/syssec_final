from hardeninspector.dex import DexFile

from .fixtures import build_dex_fixture, const_string_instruction, invoke_static_instruction


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
    assert parsed.code_methods[0].name == "<clinit>"


def test_dex_parser_returns_empty_evidence_for_invalid_dex():
    parsed = DexFile.parse("bad.dex", b"not a dex")

    assert parsed.strings == []
    assert parsed.type_descriptors == []
    assert parsed.methods == []
    assert parsed.parse_errors

