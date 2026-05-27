import struct
import zipfile

from hardeninspector.apk import ApkArchive
from hardeninspector.axml import extract_axml_strings
from hardeninspector.util import extract_printable_strings, shannon_entropy


def _string_pool(strings: list[str]) -> bytes:
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


def test_apk_archive_lists_core_artifacts(tmp_path):
    apk_path = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk_path, "w") as apk:
        apk.writestr("AndroidManifest.xml", _string_pool(["com.example.App"]))
        apk.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 40)
        apk.writestr("lib/arm64-v8a/libjiagu.so", b"JNI_OnLoad\x00/proc/self/maps")
        apk.writestr("assets/payload.bin", bytes(range(256)))

    archive = ApkArchive.open(apk_path)

    assert [entry.name for entry in archive.entries] == [
        "AndroidManifest.xml",
        "classes.dex",
        "lib/arm64-v8a/libjiagu.so",
        "assets/payload.bin",
    ]
    assert archive.manifest == _string_pool(["com.example.App"])
    assert len(archive.dex_files) == 1
    assert archive.dex_files[0].name == "classes.dex"
    assert archive.native_libraries[0].name == "lib/arm64-v8a/libjiagu.so"
    assert archive.resource_entries[0].name == "assets/payload.bin"
    assert archive.get_entry("missing") is None


def test_entropy_and_printable_string_extraction_are_stable():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 16) == 0.0
    assert shannon_entropy(bytes(range(256))) > 7.9

    strings = extract_printable_strings(
        b"\x00short no\x00DexClassLoader\x00/proc/self/status\x00",
        min_length=8,
    )

    assert "DexClassLoader" in strings
    assert "/proc/self/status" in strings
    assert "short no" in strings


def test_extract_axml_strings_reads_utf8_string_pool():
    blob = _string_pool(
        [
            "com.qihoo.util.StubApp",
            "android.permission.INTERNET",
            "ro.kernel.qemu",
        ]
    )

    assert extract_axml_strings(blob) == [
        "com.qihoo.util.StubApp",
        "android.permission.INTERNET",
        "ro.kernel.qemu",
    ]

