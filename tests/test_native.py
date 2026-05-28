from hardeninspector.native import extract_elf_symbols
from hardeninspector.synthetic import build_elf_shared_object


def test_elf_symbol_parser_extracts_dynamic_symbols():
    elf = build_elf_shared_object(["JNI_OnLoad", "ptrace", "android_dlopen_ext"])

    symbols = extract_elf_symbols(elf)

    by_name = {symbol.name: symbol for symbol in symbols}
    assert {"JNI_OnLoad", "ptrace", "android_dlopen_ext"}.issubset(by_name)
    assert by_name["ptrace"].symbol_type == "function"
    assert by_name["android_dlopen_ext"].table == ".dynsym"


def test_elf_symbol_parser_ignores_non_elf_data():
    assert extract_elf_symbols(b"JNI_OnLoad\x00ptrace\x00not an ELF") == []
