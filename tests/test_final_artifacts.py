from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_final_summary_report_and_beamer_exist():
    report = ROOT / "reports" / "final_summary.md"
    slides = ROOT / "slides" / "final_presentation.tex"

    assert report.exists()
    assert slides.exists()

    report_text = report.read_text(encoding="utf-8")
    slides_text = slides.read_text(encoding="utf-8")

    assert "HardenInspector" in report_text
    assert "开源实现对比" in report_text
    assert "Micro F1" in report_text
    assert "\\documentclass" in slides_text
    assert "\\begin{document}" in slides_text
    assert "HardenInspector" in slides_text

