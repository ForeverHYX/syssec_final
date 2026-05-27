"""Reproducible dataset construction for the final exhibit."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from pathlib import Path

from .report import scan_apk
from .synthetic import SyntheticApkSpec, build_synthetic_apk


DATASET_VERSION = "hardeninspector_eval_v1"


@dataclass(frozen=True)
class DatasetSampleSpec:
    sample_id: str
    apk_name: str
    source_plan: str
    construction: str
    expected_findings: list[str]
    apk_spec: SyntheticApkSpec


HIGH_ENTROPY_PAYLOAD = bytes(range(256)) * 2


DATASET_SPECS: tuple[DatasetSampleSpec, ...] = (
    DatasetSampleSpec(
        sample_id="fdroid_clean_baseline",
        apk_name="fdroid_clean_baseline.apk",
        source_plan="F-Droid baseline",
        construction=(
            "synthetic substitute for a benign open-source app: normal package names, "
            "readable class descriptors, no packer libraries, no anti-analysis strings"
        ),
        expected_findings=[],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["org.fdroid.example", "org.fdroid.example.MainActivity"],
            class_descriptors=[
                "Lorg/fdroid/example/MainActivity;",
                "Lorg/fdroid/example/SettingsActivity;",
                "Lorg/fdroid/example/RepositoryClient;",
            ],
            method_names=["<clinit>", "onCreate", "fetchIndex"],
            dex_strings=["https://example.invalid/index.xml", "android.permission.INTERNET"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="self_written_environment_checks",
        apk_name="self_written_environment_checks.apk",
        source_plan="self-written APK with environment checks",
        construction=(
            "synthetic self-written sample containing emulator and debugger probe strings "
            "without packer or obfuscation signals"
        ),
        expected_findings=[
            "environment.system_properties",
            "environment.debugger_probe",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.envcheck", "edu.syssec.envcheck.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/envcheck/MainActivity;",
                "Ledu/syssec/envcheck/EnvironmentProbe;",
                "Ledu/syssec/envcheck/DebugProbe;",
            ],
            method_names=["<clinit>", "checkEnvironment", "checkDebugger"],
            dex_strings=[
                "ro.kernel.qemu",
                "ro.build.fingerprint",
                "isDebuggerConnected",
                "/proc/self/status",
            ],
            const_string_values=["ro.kernel.qemu"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="r8_identifier_obfuscation",
        apk_name="r8_identifier_obfuscation.apk",
        source_plan="ProGuard/R8 controlled obfuscation",
        construction=(
            "synthetic substitute for R8/ProGuard output: package structure is retained "
            "but simple class identifiers are shortened to one-character names"
        ),
        expected_findings=["obfuscation.short_identifiers"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.r8", "com.example.r8.a"],
            class_descriptors=["La/a;", "Lb/b;", "Lc/c;", "Ld/d;"],
            method_names=["<clinit>", "a", "b"],
            dex_strings=["normal application string"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="obfuscapk_reflection_dynamic",
        apk_name="obfuscapk_reflection_dynamic.apk",
        source_plan="Obfuscapk-style controlled obfuscation",
        construction=(
            "synthetic substitute for Obfuscapk transformations: reflection and dynamic "
            "loading strings model Reflection and advanced loading passes"
        ),
        expected_findings=[
            "packer.dynamic_code_loading",
            "obfuscation.reflection",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.obfuscapk", "com.example.obfuscapk.MainActivity"],
            class_descriptors=[
                "Lcom/example/obfuscapk/MainActivity;",
                "Lcom/example/obfuscapk/ReflectiveDispatcher;",
                "Lcom/example/obfuscapk/DynamicLoader;",
            ],
            method_names=["<clinit>", "invoke", "dispatch"],
            dex_strings=[
                "DexClassLoader",
                "PathClassLoader",
                "java.lang.reflect.Method",
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="packer_stub_payload",
        apk_name="packer_stub_payload.apk",
        source_plan="packer-protected sample",
        construction=(
            "synthetic substitute for a commercial packer sample: known shell library name, "
            "manifest StubApp, high-entropy asset payload, and dynamic loading string"
        ),
        expected_findings=[
            "packer.known_library",
            "packer.stub_application",
            "packer.high_entropy_payload",
            "packer.dynamic_code_loading",
            "native.jni_entrypoint",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.packed", "com.qihoo.util.StubApp"],
            class_descriptors=[
                "Lcom/example/packed/ShellApplication;",
                "Lcom/example/packed/Loader;",
                "Lcom/example/packed/Bridge;",
            ],
            method_names=["<clinit>", "load"],
            dex_strings=["DexClassLoader"],
            native_libraries={
                "lib/arm64-v8a/libjiagu.so": b"JNI_OnLoad\x00shell loader\x00",
            },
            assets={"assets/encrypted_payload.bin": HIGH_ENTROPY_PAYLOAD},
        ),
    ),
    DatasetSampleSpec(
        sample_id="bangcle_stub_payload",
        apk_name="bangcle_stub_payload.apk",
        source_plan="Bangcle-style packer sample",
        construction=(
            "synthetic substitute for a second commercial packer family: Bangcle-like "
            "manifest namespace, known shell library, high-entropy asset, and dynamic loading"
        ),
        expected_findings=[
            "packer.known_library",
            "packer.stub_application",
            "packer.high_entropy_payload",
            "packer.dynamic_code_loading",
            "native.jni_entrypoint",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.bangcle", "com.secapk.wrapper.ApplicationWrapper", "bangcle"],
            class_descriptors=[
                "Lcom/example/bangcle/MainActivity;",
                "Lcom/example/bangcle/ShellLoader;",
                "Lcom/example/bangcle/NativeBridge;",
            ],
            method_names=["<clinit>", "load"],
            dex_strings=["DexClassLoader", "BaseDexClassLoader"],
            native_libraries={
                "lib/armeabi-v7a/libsecexe.so": b"JNI_OnLoad\x00bangcle shell\x00",
                "lib/arm64-v8a/libsecmain.so": b"JNI_OnLoad\x00sec main\x00",
            },
            assets={"assets/bangcle_payload.dat": HIGH_ENTROPY_PAYLOAD},
        ),
    ),
    DatasetSampleSpec(
        sample_id="native_jni_bridge_only",
        apk_name="native_jni_bridge_only.apk",
        source_plan="native bridge control sample",
        construction=(
            "synthetic APK with a normal Java layer and one app-owned native library that "
            "exports JNI entrypoint strings, without packer library names or anti-analysis strings"
        ),
        expected_findings=["native.jni_entrypoint"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.nativebridge", "com.example.nativebridge.MainActivity"],
            class_descriptors=[
                "Lcom/example/nativebridge/MainActivity;",
                "Lcom/example/nativebridge/NativeBridge;",
                "Lcom/example/nativebridge/CryptoHelper;",
            ],
            method_names=["<clinit>", "callNative"],
            dex_strings=["native bridge demo"],
            native_libraries={
                "lib/arm64-v8a/libnativebridge.so": b"JNI_OnLoad\x00Java_com_example_nativebridge_call\x00",
            },
        ),
    ),
    DatasetSampleSpec(
        sample_id="frida_xposed_probe",
        apk_name="frida_xposed_probe.apk",
        source_plan="instrumentation-detection sample",
        construction=(
            "synthetic self-written sample focused on runtime instrumentation probes such as "
            "Frida, Xposed, Substrate, and process-map checks"
        ),
        expected_findings=["environment.instrumentation_probe"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.instrumentation", "edu.syssec.instrumentation.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/instrumentation/MainActivity;",
                "Ledu/syssec/instrumentation/HookProbe;",
                "Ledu/syssec/instrumentation/ProcessMapReader;",
            ],
            method_names=["<clinit>", "checkHooks"],
            dex_strings=["frida", "xposed", "substrate", "/proc/self/maps", "libfrida"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="reflection_only_dispatch",
        apk_name="reflection_only_dispatch.apk",
        source_plan="reflection-only obfuscation sample",
        construction=(
            "synthetic sample isolating reflection dispatch without dynamic loading or packer "
            "library signals, so obfuscation recall can be evaluated separately"
        ),
        expected_findings=["obfuscation.reflection"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.reflectonly", "com.example.reflectonly.MainActivity"],
            class_descriptors=[
                "Lcom/example/reflectonly/MainActivity;",
                "Lcom/example/reflectonly/ReflectiveDispatcher;",
                "Lcom/example/reflectonly/TargetApi;",
            ],
            method_names=["<clinit>", "invoke", "dispatch"],
            dex_strings=["java.lang.reflect.Method", "Method.invoke"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="combined_hardened_showcase",
        apk_name="combined_hardened_showcase.apk",
        source_plan="combined hardened showcase",
        construction=(
            "synthetic sample combining all report dimensions: packer-like shell, "
            "identifier obfuscation, reflection/dynamic loading, emulator checks, debugger "
            "checks, and instrumentation probes"
        ),
        expected_findings=[
            "packer.known_library",
            "packer.stub_application",
            "packer.high_entropy_payload",
            "packer.dynamic_code_loading",
            "obfuscation.short_identifiers",
            "obfuscation.reflection",
            "environment.system_properties",
            "environment.debugger_probe",
            "environment.instrumentation_probe",
            "native.jni_entrypoint",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.combined", "com.qihoo.util.StubApp"],
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
            assets={"assets/payload.bin": HIGH_ENTROPY_PAYLOAD},
            const_string_values=["ro.kernel.qemu"],
        ),
    ),
)


def build_dataset(output_dir: str | Path) -> dict[str, object]:
    root = Path(output_dir)
    apks_dir = root / "apks"
    reports_dir = root / "reports"
    apks_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    labels: dict[str, object] = {
        "dataset_version": DATASET_VERSION,
        "description": (
            "Deterministic synthetic evaluation dataset for HardenInspector. "
            "Samples model the dataset categories promised by the midterm report "
            "without requiring commercial APKs, F-Droid downloads, Android SDK builds, "
            "or dynamic Frida infrastructure."
        ),
        "samples": [],
    }

    for spec in DATASET_SPECS:
        apk_path = apks_dir / spec.apk_name
        build_synthetic_apk(apk_path, spec.apk_spec)
        report = scan_apk(apk_path)
        report_path = reports_dir / f"{spec.sample_id}.json"
        report_path.write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        labels["samples"].append(
            {
                "id": spec.sample_id,
                "apk_path": str(Path("apks") / spec.apk_name),
                "report_path": str(Path("reports") / f"{spec.sample_id}.json"),
                "source_plan": spec.source_plan,
                "construction": spec.construction,
                "expected_findings": spec.expected_findings,
                "actual_summary": report.summary,
                "actual_findings": [finding.id for finding in report.findings],
            }
        )

    labels_path = root / "labels.json"
    labels_path.write_text(json.dumps(labels, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "README.md").write_text(_dataset_readme(), encoding="utf-8")
    return {
        "dataset_version": DATASET_VERSION,
        "output_dir": str(root),
        "sample_count": len(DATASET_SPECS),
        "labels_path": str(labels_path),
    }


def _dataset_readme() -> str:
    return """# HardenInspector Evaluation Dataset v1

This directory is generated by:

```bash
python -m hardeninspector.dataset datasets/hardeninspector_eval_v1
```

It contains deterministic synthetic APKs, labels, and HardenInspector JSON reports.
The samples correspond to the dataset categories described in the midterm report:

- F-Droid-style clean baseline
- self-written environment-detection APK
- ProGuard/R8-style identifier obfuscation
- Obfuscapk-style reflection and dynamic loading
- packer-like stub/payload APK
- second packer-family stub/payload APK
- native JNI bridge control sample
- instrumentation-probe sample
- reflection-only dispatch sample
- combined hardening showcase

The dataset intentionally avoids shipping real commercial or malicious APKs.
See `labels.json` for each sample's source-plan mapping, construction method,
expected findings, and actual detector output.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the HardenInspector evaluation dataset")
    parser.add_argument(
        "output_dir",
        nargs="?",
        default="datasets/hardeninspector_eval_v1",
        help="directory where APKs, labels, and reports will be written",
    )
    args = parser.parse_args(argv)
    manifest = build_dataset(args.output_dir)
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
