from hardeninspector.features import extract_features
from hardeninspector.report import scan_apk
from hardeninspector.rules import evaluate_rules

from .fixtures import (
    SyntheticApkSpec,
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
