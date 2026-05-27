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


def test_beamer_uses_zju_template_and_ignores_build_outputs():
    slides_dir = ROOT / "slides"
    slides_text = (slides_dir / "final_presentation.tex").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert (slides_dir / "zju_beamer.sty").exists()
    assert (slides_dir / "figures" / "background.png").exists()
    assert (slides_dir / "figures" / "logo.pdf").exists()
    assert "\\usepackage{zju_beamer}" in slides_text
    assert "\\title[HardenInspector]{HardenInspector}" in slides_text
    assert "洪奕迅、蒋城昊、项康" in slides_text
    assert "\\begin{table}" in slides_text
    assert "\\begin{tikzpicture}" in slides_text
    assert "slides/final_presentation.pdf" in gitignore
    assert "slides/*.aux" in gitignore
    assert "slides/*.log" in gitignore
