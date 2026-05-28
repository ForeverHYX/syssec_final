from hardeninspector.features import extract_features
from hardeninspector.report import scan_apk
from hardeninspector.rules import evaluate_rules

from .fixtures import (
    SyntheticApkSpec,
    build_elf_shared_object,
    build_hardened_apk,
    build_synthetic_apk,
    goto_instruction,
    if_eq_instruction,
    packed_switch_instruction,
)


def test_detector_reports_packer_obfuscation_and_environment_findings(tmp_path):
    apk_path = build_hardened_apk(tmp_path / "hardened.apk")

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "packer.known_library" in finding_ids
    assert "packer.stub_application" in finding_ids
    assert "packer.high_entropy_payload" in finding_ids
    assert "packer.dynamic_code_loading" in finding_ids
    assert "obfuscation.short_identifiers" in finding_ids
    assert "obfuscation.reflection" in finding_ids
    assert "environment.system_properties" in finding_ids
    assert "environment.debugger_probe" in finding_ids
    assert "environment.instrumentation_probe" in finding_ids
    assert "native.jni_entrypoint" in finding_ids
    assert report.summary["packer"] >= 4
    assert report.summary["obfuscation"] >= 2
    assert report.summary["environment"] >= 3


def test_features_preserve_concrete_evidence_locations(tmp_path):
    apk_path = build_hardened_apk(tmp_path / "hardened.apk")

    features = extract_features(apk_path)
    findings = evaluate_rules(features)
    known_library = next(finding for finding in findings if finding.id == "packer.known_library")
    env = next(finding for finding in findings if finding.id == "environment.system_properties")

    assert known_library.evidence[0].location == "lib/arm64-v8a/libjiagu.so"
    assert known_library.evidence[0].value == "libjiagu.so"
    assert any(item.value == "ro.kernel.qemu" for item in env.evidence)
    assert features.dex_files[0].const_strings == ["ro.kernel.qemu"]


def test_detector_reports_lightweight_control_flow_density(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "flow.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.flow", "com.example.flow.MainActivity"],
            class_descriptors=[
                "Lcom/example/flow/MainActivity;",
                "Lcom/example/flow/Dispatcher;",
                "Lcom/example/flow/StateMachine;",
            ],
            method_names=["<clinit>", "dispatch"],
            dex_strings=["control flow sample"],
            code_units=[
                *if_eq_instruction(),
                *if_eq_instruction(),
                *if_eq_instruction(),
                *goto_instruction(),
                *goto_instruction(),
                *packed_switch_instruction(),
                0x000E,
                0x000E,
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "obfuscation.control_flow_density")

    assert finding.category == "obfuscation"
    assert finding.evidence[0].kind == "dex-opcode-stat"
    assert "control_flow_density=0.75" in finding.evidence[0].value


def test_detector_reports_native_structural_symbol_findings(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "native-symbols.apk",
        SyntheticApkSpec(
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
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "native.jni_entrypoint" in finding_ids
    assert "environment.native_debugger_symbol" in finding_ids
    assert "packer.native_dynamic_loader" in finding_ids
    native_debug = next(finding for finding in report.findings if finding.id == "environment.native_debugger_symbol")
    assert native_debug.evidence[0].kind == "elf-symbol"
    assert native_debug.evidence[0].location == "lib/arm64-v8a/libnativeprobe.so:.dynsym"


def test_detector_reports_class_forname_reflection(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "class-forname.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.forname", "com.example.forname.MainActivity"],
            class_descriptors=[
                "Lcom/example/forname/MainActivity;",
                "Lcom/example/forname/ReflectiveFactory;",
            ],
            method_names=["<clinit>", "load"],
            dex_strings=["Ljava/lang/Class;", "forName", "com.example.HiddenImpl"],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "obfuscation.reflection")

    assert finding.category == "obfuscation"
    assert any(item.value == "forName" for item in finding.evidence)
    assert all(item.kind in {"dex-string", "dex-const-string", "method"} for item in finding.evidence)


def test_support_library_reflection_scaffold_is_not_obfuscation(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "support-reflection.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.supportonly", "com.example.supportonly.MainActivity"],
            class_descriptors=[
                "Landroid/support/v7/widget/SearchView$AutoCompleteTextViewReflector;",
                "Ljava/lang/Class;",
                "Ljava/lang/reflect/Method;",
            ],
            method_names=["<clinit>", "getDeclaredMethod", "invoke", "forName"],
            dex_strings=[
                "Ljava/lang/Class;",
                "java/lang/reflect/Method",
                "forName",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "obfuscation.reflection" not in finding_ids


def test_app_owned_reflection_dispatch_remains_obfuscation(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "app-reflection.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.reflective", "com.example.reflective.MainActivity"],
            class_descriptors=[
                "Lcom/example/reflective/ReflectiveDispatcher;",
                "Ljava/lang/Class;",
                "Ljava/lang/reflect/Method;",
            ],
            method_names=["<clinit>", "getDeclaredMethod", "invoke"],
            dex_strings=["java/lang/reflect/Method"],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "obfuscation.reflection")

    assert finding.category == "obfuscation"
    assert any("ReflectiveDispatcher" in item.value for item in finding.evidence)


def test_detector_reports_emulator_file_artifacts(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "emulator-files.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.emufile", "edu.syssec.emufile.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/emufile/MainActivity;",
                "Ledu/syssec/emufile/ArtifactProbe;",
            ],
            method_names=["<clinit>", "checkFiles"],
            dex_strings=[
                "/proc/ioports",
                "/sys/devices/virtual/misc/android_adb",
                "goldfish",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.emulator_artifacts")

    assert finding.category == "environment"
    assert any(item.value == "/proc/ioports" for item in finding.evidence)


def test_detector_reports_telephony_identifier_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "imei-probe.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.imei", "edu.syssec.imei.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/imei/MainActivity;",
                "Ledu/syssec/imei/TelephonyProbe;",
            ],
            method_names=["<clinit>", "checkImei"],
            dex_strings=[
                "Landroid/telephony/TelephonyManager;",
                "getDeviceId",
                "imei",
                "000000000000000",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.telephony_identifier_probe")

    assert finding.category == "environment"
    assert any(item.value == "000000000000000" for item in finding.evidence)


def test_detector_reports_signature_integrity_check(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "signature-integrity.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.integrity", "edu.syssec.integrity.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/integrity/MainActivity;",
                "Ledu/syssec/integrity/SignatureVerifier;",
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
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.integrity_check")

    assert finding.category == "environment"
    assert any(item.value == "GET_SIGNATURES" for item in finding.evidence)
    assert any(item.value == "MessageDigest" for item in finding.evidence)


def test_package_manager_metadata_lookup_is_not_integrity_check(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "package-metadata.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.metadata", "edu.syssec.metadata.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/metadata/MainActivity;",
                "Ledu/syssec/metadata/AboutScreen;",
            ],
            method_names=["<clinit>", "loadVersion", "getPackageInfo"],
            dex_strings=[
                "Landroid/content/pm/PackageManager;",
                "getPackageInfo",
                "versionName",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "environment.integrity_check" not in finding_ids


def test_detector_reports_root_artifact_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "root-artifacts.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.rootprobe", "edu.syssec.rootprobe.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/rootprobe/MainActivity;",
                "Ledu/syssec/rootprobe/RootProbe;",
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
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.root_artifact_probe")

    assert finding.category == "environment"
    assert any(item.value == "/system/xbin/su" for item in finding.evidence)
    assert any(item.value == "com.topjohnwu.magisk" for item in finding.evidence)


def test_detector_reports_java_debug_api_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "java-debug-api.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.debugapi", "edu.syssec.debugapi.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/debugapi/MainActivity;",
                "Ledu/syssec/debugapi/DebugApiProbe;",
            ],
            method_names=["<clinit>", "checkDebugger", "waitingForDebugger"],
            dex_strings=[
                "Landroid/os/Debug;",
                "waitingForDebugger",
                "android.os.Debug",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.debugger_probe")

    assert finding.category == "environment"
    assert any(item.value == "waitingForDebugger" for item in finding.evidence)
    assert any(item.value == "Landroid/os/Debug;" for item in finding.evidence)


def test_debug_logging_strings_are_not_debugger_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "debug-logging.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.debuglog", "edu.syssec.debuglog.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/debuglog/MainActivity;",
                "Ledu/syssec/debuglog/DebugLogger;",
            ],
            method_names=["<clinit>", "writeDebugLog"],
            dex_strings=["debug", "debuggable", "debug logging enabled", "waiting room"],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "environment.debugger_probe" not in finding_ids


def test_detector_reports_adb_developer_settings_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "adb-settings.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.adbprobe", "edu.syssec.adbprobe.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/adbprobe/MainActivity;",
                "Ledu/syssec/adbprobe/DeveloperSettingsProbe;",
            ],
            method_names=["<clinit>", "checkAdb", "getInt"],
            dex_strings=[
                "Landroid/provider/Settings$Secure;",
                "Landroid/provider/Settings$Global;",
                "ADB_ENABLED",
                "development_settings_enabled",
                "adb_enabled",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "environment.adb_settings_probe")

    assert finding.category == "environment"
    assert any(item.value == "ADB_ENABLED" for item in finding.evidence)
    assert any(item.value == "Landroid/provider/Settings$Secure;" for item in finding.evidence)


def test_adb_word_alone_is_not_adb_settings_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "adb-docs.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.adbdocs", "edu.syssec.adbdocs.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/adbdocs/MainActivity;",
                "Ledu/syssec/adbdocs/HelpScreen;",
            ],
            method_names=["<clinit>", "showHelp"],
            dex_strings=["adb", "adb backup is deprecated", "https://example.invalid/adb-help"],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "environment.adb_settings_probe" not in finding_ids


def test_regular_words_containing_su_are_not_root_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "regular-strings.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.regular", "edu.syssec.regular.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/regular/MainActivity;",
                "Ledu/syssec/regular/SupportScreen;",
            ],
            method_names=["<clinit>", "submitSupportRequest"],
            dex_strings=["support", "subscribe", "sunset", "result"],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "environment.root_artifact_probe" not in finding_ids


def test_telephony_sink_phone_number_is_not_emulator_probe(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "telephony-source.apk",
        SyntheticApkSpec(
            manifest_strings=["edu.syssec.telephony", "edu.syssec.telephony.MainActivity"],
            class_descriptors=[
                "Ledu/syssec/telephony/MainActivity;",
                "Ledu/syssec/telephony/SourceSinkExample;",
            ],
            method_names=["<clinit>", "send"],
            dex_strings=[
                "Landroid/telephony/TelephonyManager;",
                "getDeviceId",
                "imei",
                "+49 123",
            ],
        ),
    )

    report = scan_apk(apk_path)
    finding_ids = {finding.id for finding in report.findings}

    assert "environment.telephony_identifier_probe" not in finding_ids


def test_detector_reports_native_jni_export_symbols(tmp_path):
    apk_path = build_synthetic_apk(
        tmp_path / "jni-export.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.jniexport", "com.example.jniexport.MainActivity"],
            class_descriptors=[
                "Lcom/example/jniexport/MainActivity;",
                "Lcom/example/jniexport/NativeBridge;",
            ],
            method_names=["<clinit>", "callNative"],
            dex_strings=["native export sample"],
            native_libraries={
                "lib/arm64-v8a/libnativeexport.so": build_elf_shared_object(
                    ["Java_com_example_jniexport_NativeBridge_callNative"]
                ),
            },
        ),
    )

    report = scan_apk(apk_path)
    finding = next(item for item in report.findings if item.id == "native.jni_export")

    assert finding.category == "native"
    assert finding.evidence[0].kind == "elf-symbol"
    assert finding.evidence[0].value == "Java_com_example_jniexport_NativeBridge_callNative"
