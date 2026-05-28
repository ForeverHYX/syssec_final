from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[1]


def test_final_summary_report_and_beamer_exist():
    report = ROOT / "reports" / "final_summary.md"
    slides = ROOT / "slides" / "final_presentation.tex"
    external_docs = ROOT / "docs" / "external_corpus.md"
    defense_docs = ROOT / "docs" / "defense_qa.md"
    demo_script = ROOT / "docs" / "live_demo_script.md"
    readme = ROOT / "README.md"

    assert report.exists()
    assert slides.exists()
    assert external_docs.exists()
    assert defense_docs.exists()
    assert demo_script.exists()

    report_text = report.read_text(encoding="utf-8")
    slides_text = slides.read_text(encoding="utf-8")
    external_text = external_docs.read_text(encoding="utf-8")
    defense_text = defense_docs.read_text(encoding="utf-8")
    demo_text = demo_script.read_text(encoding="utf-8")
    readme_text = readme.read_text(encoding="utf-8")

    assert "HardenInspector" in report_text
    assert "开源实现对比" in report_text
    assert "Micro F1" in report_text
    assert "外部现成 APK" in report_text
    assert "DroidBench" in external_text
    assert "F-Droid" in external_text
    assert "\\documentclass" in slides_text
    assert "\\begin{document}" in slides_text
    assert "HardenInspector" in slides_text
    assert "外部 APK 语料" in slides_text
    assert "现场 Web Demo" in slides_text
    assert "Exhibit Map" in slides_text
    assert "Dataset Story" in slides_text
    assert "Scan Upload" in slides_text
    assert "Synthetic Oracle" in slides_text
    assert "External APK Corpus" in slides_text
    assert "这轮" not in slides_text
    assert "本轮" not in slides_text
    assert "下一步" not in slides_text
    assert "后续扩展" not in slides_text
    assert "这轮" not in report_text
    assert "本轮" not in report_text
    assert "HardenInspector Micro F1 = 1.000" in defense_text
    assert "droidbench_reflection_5" in defense_text
    assert "support-library-only" in defense_text
    assert "make demo-web" in demo_text
    assert "Scan Upload" in demo_text
    assert "docs/defense_qa.md" in readme_text
    assert "docs/live_demo_script.md" in readme_text


def test_beamer_uses_zju_template_and_ignores_build_outputs():
    slides_dir = ROOT / "slides"
    slides_text = (slides_dir / "final_presentation.tex").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert (slides_dir / "zju_beamer.sty").exists()
    assert (slides_dir / "figures" / "background.png").exists()
    assert (slides_dir / "figures" / "logo.pdf").exists()
    assert (slides_dir / "figures" / "apk_static_analysis_cutaway.png").exists()
    assert "\\usepackage{zju_beamer}" in slides_text
    assert "\\title[HardenInspector]{HardenInspector}" in slides_text
    assert "洪奕迅、蒋城昊、项康" in slides_text
    assert "\\begin{table}" in slides_text
    assert "\\begin{tikzpicture}" in slides_text
    assert "apk_static_analysis_cutaway.png" in slides_text
    assert "slides/final_presentation.pdf" in gitignore
    assert "slides/*.aux" in gitignore
    assert "slides/*.log" in gitignore


def test_rules_document_covers_dataset_findings():
    labels = json.loads((ROOT / "datasets" / "hardeninspector_eval_v1" / "labels.json").read_text(encoding="utf-8"))
    rules_text = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")

    finding_ids = {
        finding_id
        for sample in labels["samples"]
        for finding_id in sample["actual_findings"]
    }

    for finding_id in sorted(finding_ids):
        assert f"### `{finding_id}`" in rules_text
