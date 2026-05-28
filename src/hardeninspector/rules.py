"""Explainable static hardening rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .dex import OpcodeProfile
from .features import ApkFeatures, StringEvidence


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    location: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "value": self.value, "location": self.location}


@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: list[Evidence]

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": [item.to_dict() for item in self.evidence],
        }


KNOWN_PACKER_LIBS = {
    "libjiagu.so": "Qihoo 360 Jiagu",
    "libjiagu_art.so": "Qihoo 360 Jiagu",
    "libsecexe.so": "Bangcle",
    "libsecmain.so": "Bangcle",
    "libDexHelper.so": "DexHelper-style shell",
    "libshell.so": "generic shell library",
    "libprotectClass.so": "Baidu-style protection",
}

STUB_APP_PATTERNS = [
    "StubApp",
    "com.qihoo",
    "secneo",
    "bangcle",
    "ijiami",
    "ali.protect",
]

DYNAMIC_LOADING_PATTERNS = [
    "DexClassLoader",
    "PathClassLoader",
    "BaseDexClassLoader",
    "InMemoryDexClassLoader",
    "loadDex",
]

CONTEXTUAL_REFLECTION_PATTERNS = [
    "java.lang.reflect.Method",
    "java/lang/reflect/Method",
]

STRONG_REFLECTION_PATTERNS = [
    "Method.invoke",
]

CLASS_FORNAME_PATTERNS = [
    "Ljava/lang/Class;",
    "java.lang.Class",
    "java/lang/Class",
]

REFLECTION_METHOD_NAMES = {
    "invoke",
    "forName",
    "getMethod",
    "getDeclaredMethod",
    "setAccessible",
    "newInstance",
}

LIBRARY_REFLECTION_OWNER_PREFIXES = (
    "Landroid/support/",
    "Landroidx/",
    "Lcom/google/android/material/",
    "Lcom/google/common/",
    "Lkotlin/",
    "Lkotlinx/",
)

PLATFORM_CLASS_PREFIXES = (
    "Landroid/",
    "Ljava/",
    "Ljavax/",
    "Ldalvik/",
)

SYSTEM_PROPERTY_PATTERNS = [
    "ro.kernel.qemu",
    "ro.build.fingerprint",
    "ro.product.model",
    "ro.hardware",
    "goldfish",
    "ranchu",
    "genymotion",
]

EMULATOR_ARTIFACT_PATTERNS = [
    "/dev/qemu_pipe",
    "/dev/socket/qemud",
    "/proc/ioports",
    "/proc/misc",
    "/sys/qemu_trace",
    "/sys/devices/virtual/misc/android_adb",
    "goldfish",
    "ranchu",
    "android-build",
]

TELEPHONY_API_PATTERNS = [
    "Landroid/telephony/TelephonyManager;",
    "android/telephony/TelephonyManager",
    "getDeviceId",
]

TELEPHONY_EMULATOR_ID_PATTERNS = [
    "000000000000000",
    "newImei",
    "zeroPos",
]

INTEGRITY_API_PATTERNS = [
    "Landroid/content/pm/PackageManager;",
    "android/content/pm/PackageManager",
    "getPackageInfo",
    "GET_SIGNATURES",
    "GET_SIGNING_CERTIFICATES",
    "SigningInfo",
    "getSigningCertificateHistory",
]

INTEGRITY_DIGEST_PATTERNS = [
    "Landroid/content/pm/Signature;",
    "android/content/pm/Signature",
    "toByteArray",
    "MessageDigest",
    "SHA-1",
    "SHA-256",
    "checkSignature",
]

ROOT_ARTIFACT_PATTERNS = [
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/xbin/busybox",
    "com.topjohnwu.magisk",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "magiskhide",
    "RootBeer",
    "test-keys",
    "which su",
]

ADB_SETTINGS_CLASS_PATTERNS = [
    "Landroid/provider/Settings$Secure;",
    "Landroid/provider/Settings$Global;",
    "android.provider.Settings$Secure",
    "android.provider.Settings$Global",
]

ADB_SETTINGS_KEY_PATTERNS = [
    "ADB_ENABLED",
    "adb_enabled",
    "development_settings_enabled",
]

DEBUGGER_PATTERNS = [
    "isDebuggerConnected",
    "/proc/self/status",
    "TracerPid",
    "ptrace",
]

JAVA_DEBUG_CLASS_PATTERNS = [
    "Landroid/os/Debug;",
    "android/os/Debug",
    "android.os.Debug",
]

JAVA_DEBUG_METHOD_PATTERNS = [
    "isDebuggerConnected",
    "waitingForDebugger",
]

INSTRUMENTATION_PATTERNS = [
    "frida",
    "xposed",
    "substrate",
    "/proc/self/maps",
    "libfrida",
]

NATIVE_DEBUGGER_SYMBOLS = [
    "ptrace",
    "prctl",
    "syscall",
]

NATIVE_DYNAMIC_LOADER_SYMBOLS = [
    "dlopen",
    "android_dlopen_ext",
    "dlsym",
    "dladdr",
]


def evaluate_rules(features: ApkFeatures) -> list[Finding]:
    findings: list[Finding] = []
    for rule in (
        _known_packer_library,
        _stub_application,
        _high_entropy_payload,
        _dynamic_code_loading,
        _short_identifiers,
        _reflection_usage,
        _control_flow_density,
        _system_properties,
        _emulator_artifacts,
        _telephony_identifier_probe,
        _integrity_check,
        _root_artifact_probe,
        _adb_settings_probe,
        _debugger_probe,
        _instrumentation_probe,
        _native_debugger_symbol,
        _native_dynamic_loader,
        _native_jni_export,
        _jni_entrypoint,
    ):
        finding = rule(features)
        if finding is not None:
            findings.append(finding)
    return findings


def _known_packer_library(features: ApkFeatures) -> Finding | None:
    evidence: list[Evidence] = []
    for entry in features.entries:
        basename = PurePosixPath(entry.name).name
        if basename in KNOWN_PACKER_LIBS:
            evidence.append(Evidence("file", basename, entry.name))
    if not evidence:
        return None
    return Finding(
        id="packer.known_library",
        category="packer",
        severity="high",
        confidence="high",
        title="Known Android packer native library",
        description="APK contains native library names associated with common Android packers.",
        evidence=evidence,
    )


def _stub_application(features: ApkFeatures) -> Finding | None:
    evidence = _string_matches(features.string_evidence, STUB_APP_PATTERNS, kinds={"manifest-string"})
    if not evidence:
        return None
    return Finding(
        id="packer.stub_application",
        category="packer",
        severity="medium",
        confidence="high",
        title="Manifest references packer stub application",
        description="Manifest strings contain application class names or package prefixes commonly used by shell stubs.",
        evidence=evidence,
    )


def _high_entropy_payload(features: ApkFeatures) -> Finding | None:
    evidence: list[Evidence] = []
    for entry in features.resource_entries:
        if entry.name.startswith("assets/") and entry.size >= 128 and entry.entropy >= 7.5:
            evidence.append(Evidence("file-stat", f"entropy={entry.entropy:.2f}, size={entry.size}", entry.name))
    if not evidence:
        return None
    return Finding(
        id="packer.high_entropy_payload",
        category="packer",
        severity="medium",
        confidence="medium",
        title="High-entropy asset payload",
        description="APK assets contain high-entropy data that may be encrypted payload material.",
        evidence=evidence[:5],
    )


def _dynamic_code_loading(features: ApkFeatures) -> Finding | None:
    evidence = _string_matches(features.string_evidence, DYNAMIC_LOADING_PATTERNS)
    if not evidence:
        return None
    return Finding(
        id="packer.dynamic_code_loading",
        category="packer",
        severity="medium",
        confidence="medium",
        title="Dynamic code loading indicators",
        description="Strings or bytecode constants reference Android class-loading APIs used by packers and plugin loaders.",
        evidence=evidence[:10],
    )


def _short_identifiers(features: ApkFeatures) -> Finding | None:
    class_names = [_simple_class_name(value) for value in features.type_descriptors if _is_class_descriptor(value)]
    if len(class_names) < 3:
        return None
    short = [name for name in class_names if 0 < len(name) <= 2]
    ratio = len(short) / len(class_names)
    if ratio < 0.6:
        return None
    evidence = [
        Evidence("stat", f"short_class_ratio={ratio:.2f} ({len(short)}/{len(class_names)})", "DEX type descriptors"),
        *[Evidence("class", value, "DEX type descriptors") for value in short[:8]],
    ]
    return Finding(
        id="obfuscation.short_identifiers",
        category="obfuscation",
        severity="medium",
        confidence="medium",
        title="Short obfuscated class identifiers",
        description="Most class descriptors use one- or two-character simple names, a common identifier-renaming signal.",
        evidence=evidence,
    )


def _reflection_usage(features: ApkFeatures) -> Finding | None:
    evidence = _reflection_string_evidence(features)
    evidence.extend(_class_forname_evidence(features))
    evidence.extend(_reflection_method_evidence(features))
    if not evidence:
        return None
    return Finding(
        id="obfuscation.reflection",
        category="obfuscation",
        severity="medium",
        confidence="medium",
        title="Reflection usage indicators",
        description="APK references reflection APIs or invoke methods that can hide direct call targets.",
        evidence=_dedupe_evidence(evidence)[:10],
    )


def _control_flow_density(features: ApkFeatures) -> Finding | None:
    evidence: list[Evidence] = []
    for dex in features.dex_files:
        profile = dex.opcode_profile
        if _is_control_flow_heavy(profile):
            evidence.append(
                Evidence(
                    "dex-opcode-stat",
                    (
                        f"control_flow_density={profile.control_flow_density:.2f} "
                        f"({profile.control_flow_count}/{profile.instruction_count}), "
                        f"if={profile.conditional_branch_count}, goto={profile.goto_count}, "
                        f"switch={profile.switch_count}, throw={profile.throw_count}"
                    ),
                    profile.dex_name,
                )
            )
    if not evidence:
        return None
    return Finding(
        id="obfuscation.control_flow_density",
        category="obfuscation",
        severity="medium",
        confidence="medium",
        title="Dense branch or jump opcode pattern",
        description=(
            "DEX bytecode contains an unusually dense mix of branch, goto, switch, or throw "
            "instructions, a lightweight signal for control-flow obfuscation that should be "
            "reviewed with surrounding code evidence."
        ),
        evidence=evidence[:5],
    )


def _system_properties(features: ApkFeatures) -> Finding | None:
    evidence = _string_matches(features.string_evidence, SYSTEM_PROPERTY_PATTERNS)
    if not evidence:
        return None
    return Finding(
        id="environment.system_properties",
        category="environment",
        severity="medium",
        confidence="high",
        title="Emulator or device-fingerprint property checks",
        description="APK references Android system properties commonly used for emulator or sandbox detection.",
        evidence=evidence[:10],
    )


def _emulator_artifacts(features: ApkFeatures) -> Finding | None:
    evidence = _string_matches(
        features.string_evidence,
        EMULATOR_ARTIFACT_PATTERNS,
        kinds={"dex-string", "dex-const-string", "manifest-string"},
    )
    if not evidence:
        return None
    return Finding(
        id="environment.emulator_artifacts",
        category="environment",
        severity="medium",
        confidence="medium",
        title="Emulator file or hardware artifact checks",
        description="APK references emulator-specific files, kernel paths, or virtual hardware identifiers.",
        evidence=evidence[:10],
    )


def _telephony_identifier_probe(features: ApkFeatures) -> Finding | None:
    string_evidence = [
        item for item in features.string_evidence if item.kind in {"dex-string", "dex-const-string", "manifest-string"}
    ]
    api_evidence = _string_matches(string_evidence, TELEPHONY_API_PATTERNS)
    id_evidence = _string_matches(string_evidence, TELEPHONY_EMULATOR_ID_PATTERNS)
    method_evidence: list[Evidence] = []
    for method in features.methods + features.invoked_methods:
        if method.name == "getDeviceId" or method.class_descriptor == "Landroid/telephony/TelephonyManager;":
            method_evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))
    if not (id_evidence and (api_evidence or method_evidence)):
        return None
    evidence = _dedupe_evidence([*api_evidence, *method_evidence, *id_evidence])
    return Finding(
        id="environment.telephony_identifier_probe",
        category="environment",
        severity="medium",
        confidence="medium",
        title="Telephony identifier emulator probe",
        description=(
            "APK checks telephony device identifiers together with zero or placeholder IMEI values "
            "commonly used in emulator-detection examples."
        ),
        evidence=evidence[:10],
    )


def _integrity_check(features: ApkFeatures) -> Finding | None:
    string_evidence = [
        item for item in features.string_evidence if item.kind in {"dex-string", "dex-const-string"}
    ]
    api_evidence = _string_matches(string_evidence, INTEGRITY_API_PATTERNS)
    digest_evidence = _string_matches(string_evidence, INTEGRITY_DIGEST_PATTERNS)
    method_evidence: list[Evidence] = []
    for method in features.methods + features.invoked_methods:
        if method.name in {
            "getSigningCertificateHistory",
            "checkSignature",
            "toByteArray",
        }:
            method_evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))

    if not (api_evidence and (digest_evidence or method_evidence)):
        return None
    evidence = _dedupe_evidence([*api_evidence, *digest_evidence, *method_evidence])
    return Finding(
        id="environment.integrity_check",
        category="environment",
        severity="medium",
        confidence="medium",
        title="Application signature or integrity check indicators",
        description=(
            "APK references package-signature APIs together with digest or signature material, "
            "a static signal for anti-tamper or self-integrity checks."
        ),
        evidence=evidence[:10],
    )


def _root_artifact_probe(features: ApkFeatures) -> Finding | None:
    string_evidence = [
        item
        for item in features.string_evidence
        if item.kind in {"manifest-string", "dex-string", "dex-const-string"}
    ]
    evidence = _string_matches(string_evidence, ROOT_ARTIFACT_PATTERNS)
    if not evidence:
        return None

    for method in features.methods + features.invoked_methods:
        if method.name in {"isRooted", "checkRoot", "detectRoot"}:
            evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))

    return Finding(
        id="environment.root_artifact_probe",
        category="environment",
        severity="medium",
        confidence="medium",
        title="Rooted-device artifact probe",
        description=(
            "APK references rooted-device artifacts, root-management packages, test-key builds, "
            "or explicit root-check commands used in anti-analysis environment checks."
        ),
        evidence=_dedupe_evidence(evidence)[:10],
    )


def _adb_settings_probe(features: ApkFeatures) -> Finding | None:
    string_evidence = [
        item
        for item in features.string_evidence
        if item.kind in {"manifest-string", "dex-string", "dex-const-string"}
    ]
    settings_class_evidence = _string_matches(string_evidence, ADB_SETTINGS_CLASS_PATTERNS)
    setting_key_evidence = _string_matches(string_evidence, ADB_SETTINGS_KEY_PATTERNS)
    if not (settings_class_evidence and setting_key_evidence):
        return None

    method_evidence: list[Evidence] = []
    for method in features.methods + features.invoked_methods:
        if method.name in {"getInt", "getString"}:
            method_evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))

    evidence = _dedupe_evidence([*settings_class_evidence, *setting_key_evidence, *method_evidence])
    return Finding(
        id="environment.adb_settings_probe",
        category="environment",
        severity="medium",
        confidence="medium",
        title="ADB or developer-settings probe",
        description=(
            "APK references Android Settings APIs together with ADB/developer-options keys, "
            "a static signal for checking whether the device is in an analysis-friendly state."
        ),
        evidence=evidence[:10],
    )


def _debugger_probe(features: ApkFeatures) -> Finding | None:
    string_evidence = [
        item
        for item in features.string_evidence
        if item.kind in {"manifest-string", "dex-string", "dex-const-string"}
    ]
    evidence = _string_matches(
        string_evidence,
        DEBUGGER_PATTERNS,
    )
    debug_class_evidence = _string_matches(string_evidence, JAVA_DEBUG_CLASS_PATTERNS)
    debug_method_string_evidence = _string_matches(string_evidence, JAVA_DEBUG_METHOD_PATTERNS)
    debug_method_evidence: list[Evidence] = []
    for method in features.methods + features.invoked_methods:
        if method.name in JAVA_DEBUG_METHOD_PATTERNS:
            debug_method_evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))
    if debug_class_evidence and (debug_method_string_evidence or debug_method_evidence):
        evidence.extend(debug_class_evidence)
        evidence.extend(debug_method_string_evidence)
        evidence.extend(debug_method_evidence)
    for method in features.methods + features.invoked_methods:
        if method.name == "isDebuggerConnected":
            evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))
    if not evidence:
        return None
    return Finding(
        id="environment.debugger_probe",
        category="environment",
        severity="medium",
        confidence="high",
        title="Debugger detection indicators",
        description="APK references debugger status APIs, Java Debug APIs, ptrace, or TracerPid process-status checks.",
        evidence=_dedupe_evidence(evidence)[:10],
    )


def _instrumentation_probe(features: ApkFeatures) -> Finding | None:
    evidence = _string_matches(features.string_evidence, INSTRUMENTATION_PATTERNS)
    if not evidence:
        return None
    return Finding(
        id="environment.instrumentation_probe",
        category="environment",
        severity="medium",
        confidence="high",
        title="Dynamic instrumentation detection indicators",
        description="APK references Frida/Xposed/Substrate or process-map strings often used to detect instrumentation.",
        evidence=evidence[:10],
    )


def _native_debugger_symbol(features: ApkFeatures) -> Finding | None:
    evidence = _native_symbol_matches(features, NATIVE_DEBUGGER_SYMBOLS)
    if not evidence:
        return None
    return Finding(
        id="environment.native_debugger_symbol",
        category="environment",
        severity="medium",
        confidence="high",
        title="Native anti-debug symbol indicators",
        description="Native ELF symbols reference debugger or process-control APIs used by anti-analysis checks.",
        evidence=evidence[:10],
    )


def _native_dynamic_loader(features: ApkFeatures) -> Finding | None:
    evidence = _native_symbol_matches(features, NATIVE_DYNAMIC_LOADER_SYMBOLS)
    if not evidence:
        return None
    return Finding(
        id="packer.native_dynamic_loader",
        category="packer",
        severity="medium",
        confidence="medium",
        title="Native dynamic loader symbol indicators",
        description="Native ELF symbols reference dynamic-loader APIs often used by shell stubs or runtime payload loaders.",
        evidence=evidence[:10],
    )


def _native_jni_export(features: ApkFeatures) -> Finding | None:
    evidence: list[Evidence] = []
    for location, symbols in features.native_symbols.items():
        for symbol in symbols:
            if symbol.name.startswith("Java_"):
                evidence.append(Evidence("elf-symbol", symbol.name, f"{location}:{symbol.table}"))
    for location, strings in features.native_strings.items():
        for value in strings:
            if value.startswith("Java_"):
                evidence.append(Evidence("native-string", value, location))
    if not evidence:
        return None
    return Finding(
        id="native.jni_export",
        category="native",
        severity="low",
        confidence="high",
        title="Exported JNI native method symbols",
        description="Native library exports Java_* JNI bridge symbols, indicating direct Java-to-native method bindings.",
        evidence=_dedupe_evidence(evidence)[:10],
    )


def _jni_entrypoint(features: ApkFeatures) -> Finding | None:
    evidence: list[Evidence] = []
    evidence.extend(_native_symbol_matches(features, ["JNI_OnLoad"]))
    for location, strings in features.native_strings.items():
        if "JNI_OnLoad" in strings:
            evidence.append(Evidence("native-string", "JNI_OnLoad", location))
    if not evidence:
        return None
    return Finding(
        id="native.jni_entrypoint",
        category="native",
        severity="low",
        confidence="medium",
        title="Native JNI entrypoint present",
        description="Native library exports or embeds JNI entrypoint strings, indicating Java-to-native execution paths.",
        evidence=_dedupe_evidence(evidence),
    )


def _native_symbol_matches(features: ApkFeatures, names: list[str]) -> list[Evidence]:
    wanted = {name.lower(): name for name in names}
    evidence: list[Evidence] = []
    for location, symbols in features.native_symbols.items():
        for symbol in symbols:
            if symbol.name.lower() in wanted:
                evidence.append(Evidence("elf-symbol", wanted[symbol.name.lower()], f"{location}:{symbol.table}"))
    return _dedupe_evidence(evidence)


def _class_forname_evidence(features: ApkFeatures) -> list[Evidence]:
    if _is_library_only_reflection_context(features):
        return []
    string_evidence = [
        item for item in features.string_evidence if item.kind in {"dex-string", "dex-const-string"}
    ]
    class_evidence = _string_matches(string_evidence, CLASS_FORNAME_PATTERNS)
    forname_evidence = _string_matches(string_evidence, ["forName"])
    if not (class_evidence and forname_evidence):
        return []
    return _dedupe_evidence([*class_evidence, *forname_evidence])


def _reflection_string_evidence(features: ApkFeatures) -> list[Evidence]:
    if _is_library_only_reflection_context(features):
        return []
    evidence = _string_matches(features.string_evidence, STRONG_REFLECTION_PATTERNS)
    if _has_application_reflection_context(features):
        evidence.extend(_string_matches(features.string_evidence, CONTEXTUAL_REFLECTION_PATTERNS))
    return _dedupe_evidence(evidence)


def _reflection_method_evidence(features: ApkFeatures) -> list[Evidence]:
    evidence: list[Evidence] = []
    library_context = _has_library_reflection_context(features)

    for method in features.methods:
        if _is_application_reflection_method(method.class_descriptor, method.name):
            evidence.append(Evidence("method", f"{method.class_descriptor}->{method.name}", "DEX method table"))

    for dex in features.dex_files:
        for code_method in dex.code_methods:
            owner = code_method.method.class_descriptor
            if _is_library_reflection_owner(owner):
                continue
            for invoked in code_method.invoked_methods:
                if not _is_reflection_api_method(invoked.class_descriptor, invoked.name):
                    continue
                if _is_platform_descriptor(owner) and library_context:
                    continue
                evidence.append(
                    Evidence(
                        "method",
                        f"{code_method.method.class_descriptor}->{code_method.method.name} calls "
                        f"{invoked.class_descriptor}->{invoked.name}",
                        "DEX code",
                    )
                )

    return _dedupe_evidence(evidence)


def _is_library_only_reflection_context(features: ApkFeatures) -> bool:
    return _has_library_reflection_context(features) and not _has_application_reflection_context(features)


def _has_library_reflection_context(features: ApkFeatures) -> bool:
    for method in features.methods:
        if _is_library_reflection_owner(method.class_descriptor) and _is_reflection_like_method(
            method.class_descriptor,
            method.name,
        ):
            return True

    for dex in features.dex_files:
        for code_method in dex.code_methods:
            if not _is_library_reflection_owner(code_method.method.class_descriptor):
                continue
            if any(
                _is_reflection_api_method(method.class_descriptor, method.name)
                for method in code_method.invoked_methods
            ):
                return True

    return False


def _has_application_reflection_context(features: ApkFeatures) -> bool:
    for method in features.methods:
        if _is_application_reflection_method(method.class_descriptor, method.name):
            return True

    for dex in features.dex_files:
        for code_method in dex.code_methods:
            owner = code_method.method.class_descriptor
            if _is_library_reflection_owner(owner):
                continue
            if _is_application_descriptor(owner) and any(
                _is_reflection_api_method(method.class_descriptor, method.name)
                for method in code_method.invoked_methods
            ):
                return True

    return False


def _is_application_reflection_method(descriptor: str, method_name: str) -> bool:
    return _is_application_descriptor(descriptor) and _is_reflection_like_method(descriptor, method_name)


def _is_reflection_like_method(descriptor: str, method_name: str) -> bool:
    lowered_descriptor = descriptor.lower()
    lowered_method = method_name.lower()
    return (
        method_name in REFLECTION_METHOD_NAMES
        or "reflect" in lowered_descriptor
        or "reflect" in lowered_method
    )


def _is_reflection_api_method(descriptor: str, method_name: str) -> bool:
    return (
        descriptor == "Ljava/lang/Class;"
        and method_name in {"forName", "getMethod", "getDeclaredMethod"}
    ) or (
        descriptor.startswith("Ljava/lang/reflect/")
        and method_name in REFLECTION_METHOD_NAMES
    )


def _is_library_reflection_owner(descriptor: str) -> bool:
    return descriptor.startswith(LIBRARY_REFLECTION_OWNER_PREFIXES)


def _is_application_descriptor(descriptor: str) -> bool:
    if not _is_class_descriptor(descriptor):
        return False
    if _is_platform_descriptor(descriptor) or _is_library_reflection_owner(descriptor):
        return False
    simple_name = _simple_class_name(descriptor)
    return simple_name != "BuildConfig" and simple_name != "R" and not simple_name.startswith("R$")


def _is_platform_descriptor(descriptor: str) -> bool:
    return descriptor.startswith(PLATFORM_CLASS_PREFIXES)


def _string_matches(
    strings: list[StringEvidence],
    patterns: list[str],
    kinds: set[str] | None = None,
) -> list[Evidence]:
    evidence: list[Evidence] = []
    lowered_patterns = [(pattern, pattern.lower()) for pattern in patterns]
    for item in strings:
        if kinds is not None and item.kind not in kinds:
            continue
        lowered = item.value.lower()
        for original, pattern in lowered_patterns:
            if pattern in lowered:
                evidence.append(Evidence(item.kind, original if len(original) < len(item.value) else item.value, item.location))
                break
    return _dedupe_evidence(evidence)


def _is_class_descriptor(value: str) -> bool:
    return value.startswith("L") and value.endswith(";") and "/" in value


def _simple_class_name(descriptor: str) -> str:
    return descriptor.removeprefix("L").removesuffix(";").split("/")[-1]


def _is_control_flow_heavy(profile: OpcodeProfile) -> bool:
    return (
        profile.instruction_count >= 8
        and profile.control_flow_count >= 5
        and profile.control_flow_density >= 0.42
    )


def _dedupe_evidence(items: list[Evidence]) -> list[Evidence]:
    result: list[Evidence] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (item.kind, item.value, item.location)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
