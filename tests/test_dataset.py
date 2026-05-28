import json
from pathlib import Path

from hardeninspector.dataset import DATASET_VERSION, build_dataset
from hardeninspector.features import extract_features
from hardeninspector.report import scan_apk
from hardeninspector.synthetic import SyntheticApkSpec, build_synthetic_apk
from hardeninspector.util import sha256_hex


ROOT = Path(__file__).resolve().parents[1]


def test_build_dataset_creates_apks_labels_and_reports(tmp_path):
    dataset_dir = tmp_path / "dataset"

    manifest = build_dataset(dataset_dir)

    labels_path = dataset_dir / "labels.json"
    assert labels_path.exists()
    labels = json.loads(labels_path.read_text(encoding="utf-8"))

    sample_ids = {sample["id"] for sample in labels["samples"]}
    assert labels["dataset_version"] == DATASET_VERSION
    assert sample_ids == {
        "bangcle_stub_payload",
        "combined_hardened_showcase",
        "control_flow_flattening",
        "class_forname_reflection",
        "emulator_file_artifacts",
        "emulator_imei_probe",
        "fdroid_clean_baseline",
        "frida_xposed_probe",
        "adb_developer_settings_probe",
        "high_entropy_payload_only",
        "java_debug_api_probe",
        "native_jni_bridge_only",
        "native_jni_export_only",
        "native_ptrace_loader",
        "obfuscapk_reflection_dynamic",
        "packer_stub_payload",
        "reflection_only_dispatch",
        "r8_identifier_obfuscation",
        "root_artifact_probe",
        "self_written_environment_checks",
        "signature_integrity_check",
    }
    assert manifest["sample_count"] == 21
    assert (dataset_dir / "README.md").exists()

    for sample in labels["samples"]:
        apk_path = dataset_dir / sample["apk_path"]
        report_path = dataset_dir / sample["report_path"]
        assert apk_path.exists(), sample["id"]
        assert report_path.exists(), sample["id"]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        finding_ids = {finding["id"] for finding in report["findings"]}
        assert set(sample["expected_findings"]).issubset(finding_ids)


def test_dataset_documents_practical_source_substitutions(tmp_path):
    dataset_dir = tmp_path / "dataset"

    build_dataset(dataset_dir)
    labels = json.loads((dataset_dir / "labels.json").read_text(encoding="utf-8"))

    by_id = {sample["id"]: sample for sample in labels["samples"]}
    assert by_id["fdroid_clean_baseline"]["source_plan"] == "F-Droid baseline"
    assert "synthetic substitute" in by_id["fdroid_clean_baseline"]["construction"]
    assert by_id["r8_identifier_obfuscation"]["source_plan"] == "ProGuard/R8 controlled obfuscation"
    assert by_id["obfuscapk_reflection_dynamic"]["source_plan"] == "Obfuscapk-style controlled obfuscation"
    assert by_id["packer_stub_payload"]["source_plan"] == "packer-protected sample"
    assert by_id["high_entropy_payload_only"]["expected_findings"] == ["packer.high_entropy_payload"]
    assert "ELF dynamic symbol" in by_id["native_ptrace_loader"]["construction"]
    assert by_id["class_forname_reflection"]["expected_findings"] == ["obfuscation.reflection"]
    assert by_id["emulator_imei_probe"]["expected_findings"] == ["environment.telephony_identifier_probe"]
    assert by_id["native_jni_export_only"]["expected_findings"] == ["native.jni_export"]
    assert by_id["adb_developer_settings_probe"]["expected_findings"] == ["environment.adb_settings_probe"]
    assert "development_settings_enabled" in by_id["adb_developer_settings_probe"]["construction"]
    assert by_id["java_debug_api_probe"]["expected_findings"] == ["environment.debugger_probe"]
    assert "waitingForDebugger" in by_id["java_debug_api_probe"]["construction"]
    assert by_id["signature_integrity_check"]["expected_findings"] == ["environment.integrity_check"]
    assert by_id["root_artifact_probe"]["expected_findings"] == ["environment.root_artifact_probe"]


def test_synthetic_apk_generation_is_byte_reproducible(tmp_path):
    spec = SyntheticApkSpec(
        manifest_strings=["com.example.repro", "com.example.repro.MainActivity"],
        class_descriptors=["Lcom/example/repro/MainActivity;"],
        dex_strings=["stable"],
    )

    first = build_synthetic_apk(tmp_path / "first.apk", spec)
    second = build_synthetic_apk(tmp_path / "second.apk", spec)

    assert first.read_bytes() == second.read_bytes()


def test_external_apk_corpus_manifest_matches_committed_files():
    corpus = ROOT / "datasets" / "external_apk_corpus_v1"
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["corpus_version"] == "external_apk_corpus_v1"
    assert len(manifest["samples"]) == 12
    sources = {sample["source"] for sample in manifest["samples"]}
    assert {"DroidBench", "F-Droid", "PIVAA"}.issubset(sources)

    for sample in manifest["samples"]:
        apk_path = corpus / sample["apk_path"]
        assert apk_path.exists(), sample["id"]
        assert sample["source_url"].startswith("https://")
        assert "expected_categories" in sample
        assert set(sample["expected_categories"]).issubset({"packer", "obfuscation", "environment", "native"})
        assert "label_basis" in sample
        assert sha256_hex(apk_path.read_bytes()) == sample["sha256"]


def test_external_jni_export_samples_are_labeled_native():
    corpus = ROOT / "datasets" / "external_apk_corpus_v1"
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))

    for sample in manifest["samples"]:
        features = extract_features(corpus / sample["apk_path"])
        has_jni_export = any(
            symbol.name.startswith("Java_")
            for symbols in features.native_symbols.values()
            for symbol in symbols
        ) or any(
            value.startswith("Java_")
            for strings in features.native_strings.values()
            for value in strings
        )
        if has_jni_export:
            assert "native" in sample["expected_categories"], sample["id"]


def test_external_reflection_labels_require_application_owned_evidence():
    corpus = ROOT / "datasets" / "external_apk_corpus_v1"
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    by_id = {sample["id"]: sample for sample in manifest["samples"]}

    reflection_1 = by_id["droidbench_reflection_1"]
    reflection_5 = by_id["droidbench_reflection_5"]

    assert "obfuscation.reflection" in {
        finding.id for finding in scan_apk(corpus / reflection_1["apk_path"]).findings
    }
    assert "obfuscation" in reflection_1["expected_categories"]

    reflection_5_findings = {
        finding.id for finding in scan_apk(corpus / reflection_5["apk_path"]).findings
    }
    assert "obfuscation.reflection" not in reflection_5_findings
    assert "obfuscation" not in reflection_5["expected_categories"]
