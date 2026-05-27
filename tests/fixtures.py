from __future__ import annotations

import zipfile
from pathlib import Path

from hardeninspector.synthetic import (
    build_axml_string_pool,
    build_dex,
    build_synthetic_apk,
    const_string_instruction,
    invoke_static_instruction,
    SyntheticApkSpec,
)

__all__ = [
    "SyntheticApkSpec",
    "build_apk",
    "build_axml_string_pool",
    "build_dex_fixture",
    "build_hardened_apk",
    "const_string_instruction",
    "invoke_static_instruction",
]

def build_dex_fixture(
    extra_strings: list[str] | None = None,
    class_descriptors: list[str] | None = None,
    method_names: list[str] | None = None,
    code_units: list[int] | None = None,
) -> bytes:
    return build_dex(
        extra_strings=extra_strings,
        class_descriptors=class_descriptors,
        method_names=method_names,
        code_units=code_units,
    )


def build_apk(path: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as apk:
        for name, data in files.items():
            apk.writestr(name, data)
    return path


def build_hardened_apk(path: Path) -> Path:
    return build_synthetic_apk(
        path,
        SyntheticApkSpec(
            manifest_strings=["com.example.app", "com.qihoo.util.StubApp"],
            class_descriptors=["La/a;", "Lb/b;", "Lc/c;"],
            method_names=["<clinit>", "invoke"],
            dex_strings=[
                "ro.kernel.qemu",
                "ro.build.fingerprint",
                "DexClassLoader",
                "java.lang.reflect.Method",
                "isDebuggerConnected",
                "/proc/self/status",
            ],
            native_libraries={
                "lib/arm64-v8a/libjiagu.so": b"JNI_OnLoad\x00/proc/self/maps\x00frida-gadget\x00",
            },
            assets={"assets/payload.bin": bytes(range(256)) * 2},
            const_string_values=["ro.kernel.qemu"],
        ),
    )
