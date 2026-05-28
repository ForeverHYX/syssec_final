from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_out_of_box_environment_files_exist_and_expose_expected_targets():
    assert (ROOT / "scripts" / "setup_env.sh").exists()
    assert (ROOT / "Makefile").exists()
    assert (ROOT / "requirements.txt").exists()
    assert (ROOT / "requirements-dev.txt").exists()
    assert (ROOT / "requirements-benchmark.txt").exists()
    assert (ROOT / "Dockerfile").exists()

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in [
        "setup:",
        "test:",
        "dataset:",
        "benchmark:",
        "external-corpus:",
        "demo:",
        "demo-web:",
        "slides:",
        "all:",
    ]:
        assert target in makefile
    assert "--tools hardeninspector apkid androguard_dex zip_string_baseline" in makefile
    assert "--score-external-corpus datasets/external_apk_corpus_v1" in makefile
    assert "--external-corpus datasets/external_apk_corpus_v1" in makefile
    assert "droidlysis" not in makefile


def test_pyproject_exposes_benchmark_extra():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "benchmark = [" in pyproject
    assert '"apkid==3.1.0"' in pyproject
    assert '"androguard==4.1.3"' in pyproject
    assert '"droidlysis==3.4.7"' not in pyproject
    assert 'hardeninspector-demo-web = "hardeninspector.demo_web:main"' in pyproject
