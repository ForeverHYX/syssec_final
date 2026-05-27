from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hardeninspector.synthetic import SyntheticApkSpec, build_synthetic_apk  # noqa: E402


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


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    output = Path(args[0]) if args else ROOT / "samples" / "demo_hardened.apk"
    output.parent.mkdir(parents=True, exist_ok=True)
    build_hardened_apk(output)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
