import json

from hardeninspector.benchmark import (
    BenchmarkDataset,
    DEFAULT_TOOLS,
    ToolPrediction,
    build_confusion_matrix,
    compute_metrics,
    evaluate_predictions,
    load_external_corpus,
    load_dataset,
    run_benchmark,
    run_external_corpus,
)
from hardeninspector.dataset import build_dataset
from hardeninspector.synthetic import SyntheticApkSpec, build_synthetic_apk


def test_metrics_count_multilabel_predictions():
    dataset = BenchmarkDataset(
        dataset_version="test",
        samples=[
            {
                "id": "clean",
                "apk_path": "clean.apk",
                "expected_categories": [],
            },
            {
                "id": "packed",
                "apk_path": "packed.apk",
                "expected_categories": ["packer", "environment"],
            },
        ],
    )
    predictions = {
        "clean": ToolPrediction(sample_id="clean", categories=[]),
        "packed": ToolPrediction(sample_id="packed", categories=["packer", "obfuscation"]),
    }

    matrix = build_confusion_matrix(dataset, predictions, ["packer", "environment", "obfuscation"])
    metrics = compute_metrics(matrix)

    assert matrix["packer"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 1}
    assert matrix["environment"] == {"tp": 0, "fp": 0, "fn": 1, "tn": 1}
    assert matrix["obfuscation"] == {"tp": 0, "fp": 1, "fn": 0, "tn": 1}
    assert metrics["macro"]["precision"] == 1 / 3
    assert metrics["macro"]["recall"] == 1 / 3
    assert metrics["micro"]["f1"] == 0.5


def test_hardeninspector_benchmark_reaches_dataset_oracle(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "hardeninspector", None)

    assert result["tool"] == "hardeninspector"
    assert result["metrics"]["micro"]["precision"] == 1.0
    assert result["metrics"]["micro"]["recall"] == 1.0
    assert result["metrics"]["micro"]["f1"] == 1.0
    assert result["coverage"]["samples_total"] == 21
    assert result["coverage"]["samples_with_results"] == 21
    assert all(sample["runtime_ms"] is None for sample in result["samples"])


def test_default_benchmark_tools_are_runnable_and_do_not_include_droidlysis():
    assert DEFAULT_TOOLS == ["hardeninspector", "apkid", "androguard_dex", "zip_string_baseline"]
    assert "droidlysis" not in DEFAULT_TOOLS


def test_run_benchmark_writes_machine_and_markdown_reports(tmp_path):
    dataset_dir = tmp_path / "dataset"
    output_dir = tmp_path / "benchmark"
    build_dataset(dataset_dir)

    manifest = run_benchmark(dataset_dir, output_dir, tools=["hardeninspector"])

    assert manifest["dataset_version"] == "hardeninspector_eval_v1"
    assert (output_dir / "benchmark_results.json").exists()
    assert (output_dir / "benchmark_summary.md").exists()
    assert (output_dir / "benchmark_metrics.csv").exists()
    payload = json.loads((output_dir / "benchmark_results.json").read_text(encoding="utf-8"))
    assert payload["tools"][0]["tool"] == "hardeninspector"
    assert "HardenInspector" in (output_dir / "benchmark_summary.md").read_text(encoding="utf-8")
    assert "tool,category,tp,fp,fn,tn,precision,recall,f1" in (
        output_dir / "benchmark_metrics.csv"
    ).read_text(encoding="utf-8")


def test_zip_string_baseline_runs_without_external_dependencies(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "zip_string_baseline", None)

    assert result["tool"] == "zip_string_baseline"
    assert result["coverage"]["samples_total"] == 21
    assert result["coverage"]["samples_with_results"] == 21
    assert result["metrics"]["micro"]["recall"] > 0


def test_zip_string_baseline_maps_signature_integrity_to_environment(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "zip_string_baseline", None)
    by_id = {sample["id"]: sample for sample in result["samples"]}

    assert by_id["signature_integrity_check"]["predicted_categories"] == ["environment"]


def test_zip_string_baseline_maps_root_artifacts_to_environment(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "zip_string_baseline", None)
    by_id = {sample["id"]: sample for sample in result["samples"]}

    assert by_id["root_artifact_probe"]["predicted_categories"] == ["environment"]


def test_zip_string_baseline_maps_java_debug_api_to_environment(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "zip_string_baseline", None)
    by_id = {sample["id"]: sample for sample in result["samples"]}

    assert by_id["java_debug_api_probe"]["predicted_categories"] == ["environment"]


def test_zip_string_baseline_maps_adb_settings_to_environment(tmp_path):
    dataset_dir = tmp_path / "dataset"
    build_dataset(dataset_dir)
    dataset = load_dataset(dataset_dir)

    result = evaluate_predictions(dataset, "zip_string_baseline", None)
    by_id = {sample["id"]: sample for sample in result["samples"]}

    assert by_id["adb_developer_settings_probe"]["predicted_categories"] == ["environment"]


def test_external_corpus_reports_distribution_without_oracle_metrics(tmp_path):
    corpus_dir = tmp_path / "external"
    apks_dir = corpus_dir / "apks"
    output_dir = tmp_path / "external-report"
    apks_dir.mkdir(parents=True)
    apk_path = build_synthetic_apk(
        apks_dir / "sample.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.external", "com.example.external.MainActivity"],
            class_descriptors=["Lcom/example/external/MainActivity;"],
            dex_strings=["DexClassLoader"],
        ),
    )
    manifest = {
        "corpus_version": "test_external",
        "samples": [
            {
                "id": "external_sample",
                "apk_path": "apks/sample.apk",
                "source": "unit-test",
                "source_context": "dynamic-loading",
                "source_url": "https://example.invalid/sample.apk",
                "sha256": "test-only",
                "expected_categories": ["packer"],
            }
        ],
    }
    (corpus_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    dataset = load_external_corpus(corpus_dir)
    result = run_external_corpus(corpus_dir, output_dir, tools=["hardeninspector"])

    assert dataset.samples[0]["absolute_apk_path"] == str(apk_path)
    assert dataset.samples[0]["expected_categories"] == ["packer"]
    assert result["corpus_version"] == "test_external"
    assert (output_dir / "external_corpus_results.json").exists()
    payload = json.loads((output_dir / "external_corpus_results.json").read_text(encoding="utf-8"))
    tool = payload["tools"][0]
    assert "metrics" not in tool
    assert tool["coverage"] == {"samples_total": 1, "samples_with_results": 1}
    assert tool["category_counts"]["packer"] == 1
    assert tool["samples"][0]["finding_ids"] == ["packer.dynamic_code_loading"]


def test_run_benchmark_can_score_external_corpus_samples(tmp_path):
    dataset_dir = tmp_path / "dataset"
    output_dir = tmp_path / "benchmark"
    corpus_dir = tmp_path / "external"
    apks_dir = corpus_dir / "apks"
    build_dataset(dataset_dir)
    apks_dir.mkdir(parents=True)
    build_synthetic_apk(
        apks_dir / "external.apk",
        SyntheticApkSpec(
            manifest_strings=["com.example.external", "com.example.external.MainActivity"],
            class_descriptors=["Lcom/example/external/MainActivity;"],
            dex_strings=["DexClassLoader"],
        ),
    )
    (corpus_dir / "manifest.json").write_text(
        json.dumps(
            {
                "corpus_version": "external_test",
                "samples": [
                    {
                        "id": "external_dynamic_loading",
                        "apk_path": "apks/external.apk",
                        "source": "unit-test",
                        "source_context": "dynamic-loading",
                        "source_url": "https://example.invalid/external.apk",
                        "sha256": "test-only",
                        "expected_categories": ["packer"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = run_benchmark(
        dataset_dir,
        output_dir,
        tools=["hardeninspector"],
        scored_external_corpus=corpus_dir,
    )

    payload = json.loads((output_dir / "benchmark_results.json").read_text(encoding="utf-8"))
    tool_result = payload["tools"][0]
    sample_ids = {sample["id"] for sample in tool_result["samples"]}

    assert manifest["dataset_version"] == "hardeninspector_eval_v1+external_test"
    assert payload["scored_external_corpus"] == "external_test"
    assert tool_result["coverage"] == {"samples_total": 22, "samples_with_results": 22}
    assert "external_dynamic_loading" in sample_ids
    assert tool_result["metrics"]["micro"]["recall"] == 1.0
