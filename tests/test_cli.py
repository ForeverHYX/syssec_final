import json
import subprocess
import sys

from .fixtures import build_hardened_apk


def test_cli_outputs_json_report(tmp_path):
    apk_path = build_hardened_apk(tmp_path / "hardened.apk")

    result = subprocess.run(
        [sys.executable, "-m", "hardeninspector", str(apk_path), "--json"],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["apk"]["path"].endswith("hardened.apk")
    assert any(item["id"] == "environment.system_properties" for item in payload["findings"])
    assert result.stderr == ""


def test_cli_human_summary_mentions_categories(tmp_path):
    apk_path = build_hardened_apk(tmp_path / "hardened.apk")

    result = subprocess.run(
        [sys.executable, "-m", "hardeninspector", str(apk_path)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "packer" in result.stdout
    assert "obfuscation" in result.stdout
    assert "environment" in result.stdout


def test_cli_creates_output_parent_directory(tmp_path):
    apk_path = build_hardened_apk(tmp_path / "hardened.apk")
    output = tmp_path / "reports" / "demo_report.json"

    result = subprocess.run(
        [sys.executable, "-m", "hardeninspector", str(apk_path), "--json", "-o", str(output)],
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == 1
