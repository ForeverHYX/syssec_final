import json

from hardeninspector.dataset import DATASET_VERSION, build_dataset
from hardeninspector.synthetic import SyntheticApkSpec, build_synthetic_apk


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
        "fdroid_clean_baseline",
        "frida_xposed_probe",
        "native_jni_bridge_only",
        "obfuscapk_reflection_dynamic",
        "packer_stub_payload",
        "reflection_only_dispatch",
        "r8_identifier_obfuscation",
        "self_written_environment_checks",
    }
    assert manifest["sample_count"] == 11
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


def test_synthetic_apk_generation_is_byte_reproducible(tmp_path):
    spec = SyntheticApkSpec(
        manifest_strings=["com.example.repro", "com.example.repro.MainActivity"],
        class_descriptors=["Lcom/example/repro/MainActivity;"],
        dex_strings=["stable"],
    )

    first = build_synthetic_apk(tmp_path / "first.apk", spec)
    second = build_synthetic_apk(tmp_path / "second.apk", spec)

    assert first.read_bytes() == second.read_bytes()
