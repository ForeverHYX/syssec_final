"""Benchmark HardenInspector against runnable open-source comparators."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
from time import perf_counter
from typing import Any

from .apk import ApkArchive
from .report import scan_apk
from .util import extract_printable_strings


DEFAULT_CATEGORIES = ["packer", "obfuscation", "environment", "native"]
DEFAULT_TOOLS = ["hardeninspector", "apkid", "androguard_dex", "zip_string_baseline"]

ZIP_BASELINE_KEYWORDS = {
    "packer": [
        "libjiagu.so",
        "libsecexe.so",
        "libsecmain.so",
        "libDexHelper.so",
        "StubApp",
        "bangcle",
        "DexClassLoader",
        "PathClassLoader",
        "BaseDexClassLoader",
    ],
    "obfuscation": ["java.lang.reflect.Method", "java/lang/reflect/Method", "Method.invoke"],
    "environment": [
        "ro.kernel.qemu",
        "ro.build.fingerprint",
        "isDebuggerConnected",
        "/proc/self/status",
        "frida",
        "xposed",
        "substrate",
        "/proc/self/maps",
    ],
    "native": ["JNI_OnLoad"],
}


@dataclass(frozen=True)
class BenchmarkDataset:
    dataset_version: str
    samples: list[dict[str, Any]]


@dataclass(frozen=True)
class ToolPrediction:
    sample_id: str
    categories: list[str]
    finding_ids: list[str] | None = None
    status: str = "ok"
    runtime_ms: float | None = None
    notes: str | None = None


def load_dataset(dataset_dir: str | Path) -> BenchmarkDataset:
    root = Path(dataset_dir)
    labels = json.loads((root / "labels.json").read_text(encoding="utf-8"))
    samples: list[dict[str, Any]] = []
    for sample in labels["samples"]:
        expected_categories = sorted(
            {
                _category_from_finding(finding_id)
                for finding_id in sample.get("expected_findings", [])
                if _category_from_finding(finding_id) in DEFAULT_CATEGORIES
            }
        )
        samples.append(
            {
                **sample,
                "absolute_apk_path": str(root / sample["apk_path"]),
                "expected_categories": expected_categories,
            }
        )
    return BenchmarkDataset(dataset_version=labels["dataset_version"], samples=samples)


def evaluate_predictions(
    dataset: BenchmarkDataset,
    tool: str,
    predictions: dict[str, ToolPrediction] | None,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    categories = categories or DEFAULT_CATEGORIES
    if predictions is None:
        predictions = _run_tool(dataset, tool)
    matrix = build_confusion_matrix(dataset, predictions, categories)
    metrics = compute_metrics(matrix)
    rows = []
    for sample in dataset.samples:
        prediction = predictions.get(
            sample["id"],
            ToolPrediction(sample_id=sample["id"], categories=[], status="missing"),
        )
        rows.append(
            {
                "id": sample["id"],
                "expected_categories": sample["expected_categories"],
                "predicted_categories": sorted(prediction.categories),
                "status": prediction.status,
                "runtime_ms": None,
                "notes": prediction.notes,
                "finding_ids": prediction.finding_ids or [],
            }
        )

    return {
        "tool": tool,
        "categories": categories,
        "coverage": {
            "samples_total": len(dataset.samples),
            "samples_with_results": sum(1 for row in rows if row["status"] == "ok"),
        },
        "confusion_matrix": matrix,
        "metrics": metrics,
        "samples": rows,
    }


def build_confusion_matrix(
    dataset: BenchmarkDataset,
    predictions: dict[str, ToolPrediction],
    categories: list[str],
) -> dict[str, dict[str, int]]:
    matrix = {category: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for category in categories}
    for sample in dataset.samples:
        expected = set(sample["expected_categories"])
        predicted = set(predictions.get(sample["id"], ToolPrediction(sample["id"], [])).categories)
        for category in categories:
            if category in expected and category in predicted:
                matrix[category]["tp"] += 1
            elif category not in expected and category in predicted:
                matrix[category]["fp"] += 1
            elif category in expected and category not in predicted:
                matrix[category]["fn"] += 1
            else:
                matrix[category]["tn"] += 1
    return matrix


def compute_metrics(matrix: dict[str, dict[str, int]]) -> dict[str, Any]:
    by_category = {}
    totals = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for category, counts in matrix.items():
        for key in totals:
            totals[key] += counts[key]
        by_category[category] = _counts_to_metrics(counts)

    macro = {
        name: sum(values[name] for values in by_category.values()) / len(by_category)
        for name in ("precision", "recall", "f1")
    }
    micro = _counts_to_metrics(totals)
    return {"by_category": by_category, "macro": macro, "micro": micro}


def run_benchmark(
    dataset_dir: str | Path,
    output_dir: str | Path,
    tools: list[str] | None = None,
) -> dict[str, Any]:
    dataset = load_dataset(dataset_dir)
    tools = tools or DEFAULT_TOOLS
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    results = {
        "schema_version": 1,
        "dataset_version": dataset.dataset_version,
        "categories": DEFAULT_CATEGORIES,
        "tools": [evaluate_predictions(dataset, tool, None) for tool in tools],
        "comparator_notes": _comparator_notes(),
    }
    (output / "benchmark_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "benchmark_summary.md").write_text(_render_markdown_summary(results), encoding="utf-8")
    (output / "benchmark_metrics.csv").write_text(_render_metrics_csv(results), encoding="utf-8")
    return {
        "dataset_version": dataset.dataset_version,
        "output_dir": str(output),
        "tools": tools,
        "results_path": str(output / "benchmark_results.json"),
        "summary_path": str(output / "benchmark_summary.md"),
        "metrics_csv_path": str(output / "benchmark_metrics.csv"),
    }


def _run_tool(dataset: BenchmarkDataset, tool: str) -> dict[str, ToolPrediction]:
    if tool == "hardeninspector":
        return _run_hardeninspector(dataset)
    if tool == "apkid":
        return _run_apkid(dataset)
    if tool == "androguard_dex":
        return _run_androguard_dex(dataset)
    if tool == "zip_string_baseline":
        return _run_zip_string_baseline(dataset)
    raise ValueError(f"unknown benchmark tool: {tool}")


def _run_hardeninspector(dataset: BenchmarkDataset) -> dict[str, ToolPrediction]:
    predictions = {}
    for sample in dataset.samples:
        start = perf_counter()
        report = scan_apk(sample["absolute_apk_path"])
        runtime_ms = (perf_counter() - start) * 1000
        predictions[sample["id"]] = ToolPrediction(
            sample_id=sample["id"],
            categories=sorted({finding.category for finding in report.findings}),
            finding_ids=[finding.id for finding in report.findings],
            runtime_ms=runtime_ms,
        )
    return predictions


def _run_apkid(dataset: BenchmarkDataset) -> dict[str, ToolPrediction]:
    apkid = shutil.which("apkid")
    if apkid is None:
        local = Path(sys.prefix) / "bin" / "apkid"
        apkid = str(local) if local.exists() else None
    if apkid is None:
        return _unavailable(dataset, "apkid executable not found")

    predictions: dict[str, ToolPrediction] = {}
    for sample in dataset.samples:
        start = perf_counter()
        result = subprocess.run(
            [apkid, "-j", sample["absolute_apk_path"]],
            check=False,
            text=True,
            capture_output=True,
        )
        runtime_ms = (perf_counter() - start) * 1000
        if result.returncode != 0:
            predictions[sample["id"]] = ToolPrediction(
                sample_id=sample["id"],
                categories=[],
                status="error",
                runtime_ms=runtime_ms,
                notes=result.stderr.strip() or result.stdout.strip(),
            )
            continue
        categories, finding_ids = _parse_apkid_json_lines(result.stdout)
        predictions[sample["id"]] = ToolPrediction(
            sample_id=sample["id"],
            categories=sorted(categories),
            finding_ids=sorted(finding_ids),
            runtime_ms=runtime_ms,
        )
    return predictions


def _parse_apkid_json_lines(output: str) -> tuple[set[str], set[str]]:
    categories: set[str] = set()
    finding_ids: set[str] = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        for file_entry in payload.get("files", []):
            matches = file_entry.get("matches", {})
            for apkid_category, values in matches.items():
                mapped = _map_apkid_category(apkid_category)
                if mapped is not None:
                    categories.add(mapped)
                    for value in values:
                        finding_ids.add(f"apkid.{apkid_category}.{value}")
    return categories, finding_ids


def _map_apkid_category(category: str) -> str | None:
    if category == "packer":
        return "packer"
    if category in {"obfuscator", "anti_disassembly"}:
        return "obfuscation"
    if category in {"anti_vm", "anti_debug"}:
        return "environment"
    return None


def _run_androguard_dex(dataset: BenchmarkDataset) -> dict[str, ToolPrediction]:
    try:
        from androguard.core.dex import DEX
        from loguru import logger
    except Exception as exc:  # pragma: no cover - depends on optional benchmark extra
        return _unavailable(dataset, f"androguard import failed: {exc}")

    logger.disable("androguard")
    predictions: dict[str, ToolPrediction] = {}
    for sample in dataset.samples:
        start = perf_counter()
        categories: set[str] = set()
        finding_ids: set[str] = set()
        notes: list[str] = []
        status = "ok"
        try:
            archive = ApkArchive.open(sample["absolute_apk_path"])
            strings: set[str] = set()
            class_names: list[str] = []
            method_names: set[str] = set()
            for dex_entry in archive.dex_files:
                dex = DEX(archive.read(dex_entry.name))
                strings.update(str(value) for value in dex.get_strings())
                for class_def in dex.get_classes():
                    descriptor = class_def.get_name()
                    strings.add(descriptor)
                    class_names.append(_simple_class_name(descriptor))
                for method in dex.get_methods():
                    method_names.add(method.get_name())
            categories, finding_ids = _categories_from_static_strings(
                strings,
                class_names=class_names,
                method_names=method_names,
                prefix="androguard",
            )
        except Exception as exc:
            status = "error"
            notes.append(_shorten(str(exc)))
        runtime_ms = (perf_counter() - start) * 1000
        predictions[sample["id"]] = ToolPrediction(
            sample_id=sample["id"],
            categories=sorted(categories),
            finding_ids=sorted(finding_ids),
            status=status,
            runtime_ms=runtime_ms,
            notes="; ".join(notes) if notes else "Androguard DEX parser baseline: DEX strings/classes/methods only.",
        )
    return predictions


def _run_zip_string_baseline(dataset: BenchmarkDataset) -> dict[str, ToolPrediction]:
    predictions: dict[str, ToolPrediction] = {}
    for sample in dataset.samples:
        start = perf_counter()
        archive = ApkArchive.open(sample["absolute_apk_path"])
        strings: set[str] = {entry.name for entry in archive.entries}
        for data in archive.files.values():
            strings.update(extract_printable_strings(data, min_length=4))
        categories, finding_ids = _categories_from_static_strings(
            strings,
            class_names=[],
            method_names=set(),
            prefix="zip_string",
        )
        runtime_ms = (perf_counter() - start) * 1000
        predictions[sample["id"]] = ToolPrediction(
            sample_id=sample["id"],
            categories=sorted(categories),
            finding_ids=sorted(finding_ids),
            runtime_ms=runtime_ms,
            notes="Raw ZIP filename/string baseline without APK/AXML/DEX structural parsing.",
        )
    return predictions


def _categories_from_static_strings(
    values: set[str],
    class_names: list[str],
    method_names: set[str],
    prefix: str,
) -> tuple[set[str], set[str]]:
    categories: set[str] = set()
    finding_ids: set[str] = set()
    lowered = {value.lower(): value for value in values}
    for category, keywords in ZIP_BASELINE_KEYWORDS.items():
        for keyword in keywords:
            if any(keyword.lower() in value for value in lowered):
                categories.add(category)
                finding_ids.add(f"{prefix}.{category}.{keyword}")
                break

    if method_names.intersection({"invoke", "getMethod", "getDeclaredMethod"}):
        categories.add("obfuscation")
        finding_ids.add(f"{prefix}.obfuscation.reflective_method")

    if len(class_names) >= 3:
        short = [name for name in class_names if 0 < len(name) <= 2]
        if len(short) / len(class_names) >= 0.6:
            categories.add("obfuscation")
            finding_ids.add(f"{prefix}.obfuscation.short_identifiers")

    return categories, finding_ids


def _simple_class_name(descriptor: str) -> str:
    value = descriptor.strip("L;")
    return value.rsplit("/", 1)[-1]


def _unavailable(dataset: BenchmarkDataset, note: str) -> dict[str, ToolPrediction]:
    return {
        sample["id"]: ToolPrediction(sample_id=sample["id"], categories=[], status="unavailable", notes=note)
        for sample in dataset.samples
    }


def _counts_to_metrics(counts: dict[str, int]) -> dict[str, float]:
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def _category_from_finding(finding_id: str) -> str:
    return finding_id.split(".", 1)[0]


def _comparator_notes() -> dict[str, str]:
    return {
        "hardeninspector": "Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.",
        "apkid": "Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.",
        "androguard_dex": "Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.",
        "zip_string_baseline": "Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.",
        "droidlysis": "Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.",
        "mobsf": "Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.",
    }


def _render_markdown_summary(results: dict[str, Any]) -> str:
    lines = [
        "# Open-source Comparator Benchmark",
        "",
        f"Dataset: `{results['dataset_version']}`",
        "",
        "## Overall Metrics",
        "",
        "| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for tool_result in results["tools"]:
        metrics = tool_result["metrics"]
        coverage = tool_result["coverage"]
        lines.append(
            "| {tool} | {seen}/{total} | {mp:.3f} | {mr:.3f} | {mf:.3f} | {maf:.3f} |".format(
                tool=_display_tool_name(tool_result["tool"]),
                seen=coverage["samples_with_results"],
                total=coverage["samples_total"],
                mp=metrics["micro"]["precision"],
                mr=metrics["micro"]["recall"],
                mf=metrics["micro"]["f1"],
                maf=metrics["macro"]["f1"],
            )
        )

    lines.extend(["", "## Per-category F1", ""])
    for tool_result in results["tools"]:
        lines.append(f"### {_display_tool_name(tool_result['tool'])}")
        lines.append("")
        lines.append("| Category | TP | FP | FN | Precision | Recall | F1 |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for category, counts in tool_result["confusion_matrix"].items():
            metric = tool_result["metrics"]["by_category"][category]
            lines.append(
                f"| {category} | {counts['tp']} | {counts['fp']} | {counts['fn']} | "
                f"{metric['precision']:.3f} | {metric['recall']:.3f} | {metric['f1']:.3f} |"
            )
        lines.append("")

    lines.extend(["## Comparator Scope Notes", ""])
    for tool, note in results["comparator_notes"].items():
        lines.append(f"- **{_display_tool_name(tool)}**: {note}")
    lines.append("")
    return "\n".join(lines)


def _render_metrics_csv(results: dict[str, Any]) -> str:
    lines = ["tool,category,tp,fp,fn,tn,precision,recall,f1"]
    for tool_result in results["tools"]:
        tool = tool_result["tool"]
        for category, counts in tool_result["confusion_matrix"].items():
            metric = tool_result["metrics"]["by_category"][category]
            lines.append(
                "{tool},{category},{tp},{fp},{fn},{tn},{precision:.6f},{recall:.6f},{f1:.6f}".format(
                    tool=tool,
                    category=category,
                    tp=counts["tp"],
                    fp=counts["fp"],
                    fn=counts["fn"],
                    tn=counts["tn"],
                    precision=metric["precision"],
                    recall=metric["recall"],
                    f1=metric["f1"],
                )
            )
        micro = tool_result["metrics"]["micro"]
        lines.append(
            "{tool},micro,,,,,{precision:.6f},{recall:.6f},{f1:.6f}".format(
                tool=tool,
                precision=micro["precision"],
                recall=micro["recall"],
                f1=micro["f1"],
            )
        )
        macro = tool_result["metrics"]["macro"]
        lines.append(
            "{tool},macro,,,,,{precision:.6f},{recall:.6f},{f1:.6f}".format(
                tool=tool,
                precision=macro["precision"],
                recall=macro["recall"],
                f1=macro["f1"],
            )
        )
    return "\n".join(lines) + "\n"


def _display_tool_name(tool: str) -> str:
    return {
        "hardeninspector": "HardenInspector",
        "apkid": "APKiD",
        "androguard_dex": "Androguard DEX",
        "zip_string_baseline": "ZIP Strings",
        "droidlysis": "DroidLysis",
        "mobsf": "MobSF",
    }.get(tool, tool)


def _shorten(value: str, limit: int = 360) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run HardenInspector reliability benchmark")
    parser.add_argument(
        "--dataset",
        default="datasets/hardeninspector_eval_v1",
        help="dataset directory containing labels.json and APKs",
    )
    parser.add_argument(
        "--output",
        default="reports/benchmark",
        help="directory where benchmark JSON/Markdown reports are written",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        default=DEFAULT_TOOLS,
        choices=["hardeninspector", "apkid", "androguard_dex", "zip_string_baseline"],
        help="tools to run",
    )
    args = parser.parse_args(argv)
    manifest = run_benchmark(args.dataset, args.output, args.tools)
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
