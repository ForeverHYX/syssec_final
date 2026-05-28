"""Reproducible dataset construction for the final exhibit."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from pathlib import Path

from .report import scan_apk
from .synthetic import (
    SyntheticApkSpec,
    build_elf_shared_object,
    build_synthetic_apk,
    goto_instruction,
    if_eq_instruction,
)


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
        sample_id="control_flow_flattening",
        apk_name="control_flow_flattening.apk",
        source_plan="control-flow obfuscation sample",
        construction=(
            "synthetic sample with a dense if/goto bytecode pattern that models "
            "lightweight control-flow flattening signals without requiring full CFG recovery"
        ),
        expected_findings=["obfuscation.control_flow_density"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.flowflat", "com.example.flowflat.MainActivity"],
            class_descriptors=[
                "Lcom/example/flowflat/MainActivity;",
                "Lcom/example/flowflat/Dispatcher;",
                "Lcom/example/flowflat/StateMachine;",
            ],
            method_names=["<clinit>", "dispatch"],
            dex_strings=["control flow flattening sample"],
            code_units=[
                *if_eq_instruction(),
                *if_eq_instruction(),
                *if_eq_instruction(),
                *goto_instruction(),
                *goto_instruction(),
                *goto_instruction(),
                0x000E,
                0x000E,
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="high_entropy_payload_only",
        apk_name="high_entropy_payload_only.apk",
        source_plan="opaque encrypted-payload control sample",
        construction=(
            "synthetic APK whose only hardening signal is a high-entropy asset payload; "
            "this exercises file-stat evidence that a plain string baseline cannot recover"
        ),
        expected_findings=["packer.high_entropy_payload"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.opaque", "com.example.opaque.MainActivity"],
            class_descriptors=[
                "Lcom/example/opaque/MainActivity;",
                "Lcom/example/opaque/FeatureController;",
                "Lcom/example/opaque/AssetReader;",
            ],
            method_names=["<clinit>", "onCreate", "openAsset"],
            dex_strings=["ordinary feature flag", "image cache"],
            assets={"assets/opaque_payload.bin": HIGH_ENTROPY_PAYLOAD},
        ),
    ),
    DatasetSampleSpec(
        sample_id="native_ptrace_loader",
        apk_name="native_ptrace_loader.apk",
        source_plan="native anti-debug and loader symbol sample",
        construction=(
            "synthetic APK with ELF dynamic symbol evidence for JNI_OnLoad, ptrace, "
            "and android_dlopen_ext; this exercises Native symbol-table parsing rather "
            "than relying only on DEX or Manifest strings"
        ),
        expected_findings=[
            "environment.native_debugger_symbol",
            "packer.native_dynamic_loader",
            "native.jni_entrypoint",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.nativeprobe", "com.example.nativeprobe.MainActivity"],
            class_descriptors=[
                "Lcom/example/nativeprobe/MainActivity;",
                "Lcom/example/nativeprobe/NativeProbe;",
                "Lcom/example/nativeprobe/Loader;",
            ],
            method_names=["<clinit>", "run"],
            dex_strings=["native symbol sample"],
            native_libraries={
                "lib/arm64-v8a/libnativeprobe.so": build_elf_shared_object(
                    ["JNI_OnLoad", "ptrace", "android_dlopen_ext"]
                ),
            },
        ),
    ),
    DatasetSampleSpec(
        sample_id="class_forname_reflection",
        apk_name="class_forname_reflection.apk",
        source_plan="Class.forName reflection sample",
        construction=(
            "synthetic sample modeled after DroidBench Reflection: class-name based reflective "
            "loading uses `Ljava/lang/Class;` and `forName` evidence without Method.invoke strings"
        ),
        expected_findings=["obfuscation.reflection"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.forname", "com.example.forname.MainActivity"],
            class_descriptors=[
                "Lcom/example/forname/MainActivity;",
                "Lcom/example/forname/ReflectiveFactory;",
                "Lcom/example/forname/HiddenImpl;",
            ],
            method_names=["<clinit>", "load"],
            dex_strings=["Ljava/lang/Class;", "forName", "com.example.HiddenImpl"],
        ),
    ),
    DatasetSampleSpec(
        sample_id="emulator_file_artifacts",
        apk_name="emulator_file_artifacts.apk",
        source_plan="emulator file-artifact sample",
        construction=(
            "synthetic sample modeled after DroidBench file-based emulator detection: "
            "DEX strings reference `/proc` and `/sys` virtual-device artifacts"
        ),
        expected_findings=[
            "environment.system_properties",
            "environment.emulator_artifacts",
        ],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.emufile", "edu.syssec.emufile.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/emufile/MainActivity;",
                "Ledu/syssec/emufile/ArtifactProbe;",
                "Ledu/syssec/emufile/FileProbe;",
            ],
            method_names=["<clinit>", "checkFiles"],
            dex_strings=[
                "/proc/ioports",
                "/sys/devices/virtual/misc/android_adb",
                "goldfish",
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="emulator_imei_probe",
        apk_name="emulator_imei_probe.apk",
        source_plan="emulator IMEI probe sample",
        construction=(
            "synthetic sample modeled after DroidBench IMEI-based emulator detection: "
            "TelephonyManager/getDeviceId is combined with zero-like device identifiers"
        ),
        expected_findings=["environment.telephony_identifier_probe"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.imei", "edu.syssec.imei.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/imei/MainActivity;",
                "Ledu/syssec/imei/TelephonyProbe;",
                "Ledu/syssec/imei/DeviceIdProbe;",
            ],
            method_names=["<clinit>", "checkImei"],
            dex_strings=[
                "Landroid/telephony/TelephonyManager;",
                "getDeviceId",
                "imei",
                "000000000000000",
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="signature_integrity_check",
        apk_name="signature_integrity_check.apk",
        source_plan="self-written anti-tamper signature check sample",
        construction=(
            "synthetic sample modeling app self-integrity checks: PackageManager signature "
            "lookup is combined with Signature/toByteArray and MessageDigest/SHA-256 evidence"
        ),
        expected_findings=["environment.integrity_check"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.integrity", "edu.syssec.integrity.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/integrity/MainActivity;",
                "Ledu/syssec/integrity/SignatureVerifier;",
                "Ledu/syssec/integrity/DigestChecker;",
            ],
            method_names=["<clinit>", "verifySignature"],
            dex_strings=[
                "Landroid/content/pm/PackageManager;",
                "getPackageInfo",
                "GET_SIGNATURES",
                "Landroid/content/pm/Signature;",
                "MessageDigest",
                "SHA-256",
                "toByteArray",
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="root_artifact_probe",
        apk_name="root_artifact_probe.apk",
        source_plan="self-written rooted-device environment check sample",
        construction=(
            "synthetic sample modeling root-detection logic: su binary paths, Superuser/Magisk "
            "package names, test-key build tags, and explicit root-check commands"
        ),
        expected_findings=["environment.root_artifact_probe"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["edu.syssec.rootprobe", "edu.syssec.rootprobe.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/rootprobe/MainActivity;",
                "Ledu/syssec/rootprobe/RootProbe;",
                "Ledu/syssec/rootprobe/MagiskProbe;",
            ],
            method_names=["<clinit>", "isRooted"],
            dex_strings=[
                "/system/xbin/su",
                "/system/app/Superuser.apk",
                "com.topjohnwu.magisk",
                "test-keys",
                "which su",
            ],
        ),
    ),
    DatasetSampleSpec(
        sample_id="native_jni_export_only",
        apk_name="native_jni_export_only.apk",
        source_plan="JNI Java_* export sample",
        construction=(
            "synthetic APK whose native evidence is an exported `Java_*` JNI method symbol "
            "without `JNI_OnLoad`, matching older NDK/DroidBench-style native samples"
        ),
        expected_findings=["native.jni_export"],
        apk_spec=SyntheticApkSpec(
            manifest_strings=["com.example.jniexport", "com.example.jniexport.MainActivity"],
            class_descriptors=[
                "Lcom/example/jniexport/MainActivity;",
                "Lcom/example/jniexport/NativeBridge;",
                "Lcom/example/jniexport/NativeFacade;",
            ],
            method_names=["<clinit>", "callNative"],
            dex_strings=["native export sample"],
            native_libraries={
                "lib/arm64-v8a/libnativeexport.so": build_elf_shared_object(
                    ["Java_com_example_jniexport_NativeBridge_callNative"]
                ),
            },
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
- lightweight control-flow flattening sample
- high-entropy payload-only sample
- native ptrace/dlopen ELF-symbol sample
- Class.forName reflection sample
- emulator file-artifact sample
- emulator IMEI probe sample
- app signature integrity-check sample
- root artifact probe sample
- JNI Java_* export sample
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
