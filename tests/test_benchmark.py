import json

from hardeninspector.benchmark import (
    BenchmarkDataset,
    ToolPrediction,
    build_confusion_matrix,
    compute_metrics,
    evaluate_predictions,
    load_dataset,
    run_benchmark,
)
from hardeninspector.dataset import build_dataset


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
    assert result["coverage"]["samples_total"] == 6
    assert result["coverage"]["samples_with_results"] == 6
    assert all(sample["runtime_ms"] is None for sample in result["samples"])


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
