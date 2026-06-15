from pathlib import Path
from io import BytesIO

import pytest

import hardeninspector.demo_web as demo_web
from hardeninspector.demo_web import (
    build_demo_catalog,
    create_handler,
    load_demo_metrics,
    render_index_html,
    scan_uploaded_apk,
    scan_demo_sample,
)


ROOT = Path(__file__).resolve().parents[1]


class _FakeSocket:
    def __init__(self, request: bytes):
        self._request = BytesIO(request)
        self.wfile = BytesIO()

    def makefile(self, mode: str, *_args):
        if "r" in mode:
            return self._request
        return self.wfile

    def sendall(self, data: bytes) -> None:
        self.wfile.write(data)


def test_demo_catalog_points_to_existing_curated_samples():
    catalog = build_demo_catalog(ROOT)
    by_id = {sample["id"]: sample for sample in catalog}

    assert {
        "fdroid_clean_baseline",
        "combined_hardened_showcase",
        "adb_developer_settings_probe",
        "installer_source_probe",
        "java_debug_api_probe",
        "signature_integrity_check",
        "root_artifact_probe",
        "pivaa",
    } <= by_id.keys()
    assert len(catalog) >= 5
    for sample in catalog:
        apk_path = Path(sample["apk_path"])
        assert apk_path.exists()
        assert apk_path.suffix == ".apk"
        assert sample["size_bytes"] > 0
        assert sample["dataset_kind"] in {"合成 Oracle", "外部 APK 语料"}
        assert sample["showcase_role"]

    assert by_id["combined_hardened_showcase"]["showcase_role"] == "四类证据链样本"
    assert by_id["adb_developer_settings_probe"]["showcase_role"] == "ADB 与开发者设置探测"
    assert by_id["installer_source_probe"]["showcase_role"] == "安装来源环境探测"
    assert by_id["java_debug_api_probe"]["showcase_role"] == "Java 层反调试 API"
    assert by_id["signature_integrity_check"]["showcase_role"] == "签名完整性与防篡改证据"
    assert by_id["root_artifact_probe"]["showcase_role"] == "Root 环境探测"
    assert by_id["fdroid_editor"]["dataset_kind"] == "外部 APK 语料"


def test_scan_demo_sample_returns_report_with_expected_signal():
    result = scan_demo_sample("combined_hardened_showcase", ROOT)

    assert result["sample"]["id"] == "combined_hardened_showcase"
    assert result["report"]["summary"]["packer"] > 0
    assert result["report"]["summary"]["environment"] > 0
    assert result["report"]["findings"]
    assert any(finding["evidence"] for finding in result["report"]["findings"])


def test_scan_uploaded_apk_scans_raw_apk_bytes():
    apk_path = ROOT / "datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk"

    result = scan_uploaded_apk(apk_path.read_bytes(), "combined_hardened_showcase.apk")

    assert result["sample"]["id"] == "uploaded"
    assert result["sample"]["source"] == "本地上传 APK"
    assert result["sample"]["dataset_kind"] == "本地上传文件"
    assert result["sample"]["showcase_role"] == "现场扫描验证"
    assert result["sample"]["size_bytes"] == apk_path.stat().st_size
    assert result["report"]["summary"]["packer"] > 0
    assert result["report"]["summary"]["environment"] > 0


def test_scan_uploaded_apk_rejects_non_apk_and_oversized_inputs():
    with pytest.raises(ValueError, match="APK"):
        scan_uploaded_apk(b"not an apk", "notes.txt")

    with pytest.raises(ValueError, match="超过"):
        scan_uploaded_apk(b"0123456789", "sample.apk", max_bytes=4)


def test_load_demo_metrics_exposes_comparison_rows():
    metrics = load_demo_metrics(ROOT)
    rows = {(row["tool"], row["category"]): row for row in metrics["rows"]}

    assert set(metrics["tools"]) == {
        "hardeninspector",
        "apkid",
        "androguard_dex",
        "zip_string_baseline",
    }
    assert rows[("hardeninspector", "micro")]["f1"] == 1.0
    assert rows[("apkid", "micro")]["f1"] < rows[("hardeninspector", "micro")]["f1"]


def test_render_index_html_contains_demo_api_surface():
    html = render_index_html()

    assert "HardenInspector 本地演示" in html
    assert "展品导览" in html
    assert "证据链" in html
    assert "数据集说明" in html
    assert "合成 Oracle" in html
    assert "外部 APK 语料" in html
    assert "HardenInspector Micro F1" in html
    assert "34 个评分 APK" in html
    assert "71 个回归测试" in html
    assert "/assets/apk-cutaway.png" in html
    assert "/api/samples" in html
    assert "/api/scan" in html
    assert "/api/scan-upload" in html
    assert "/api/metrics" in html
    assert "上传 APK" in html
    assert "扫描上传文件" in html
    assert "证据" in html
    assert "动态验证独立页" not in html
    assert 'href="/dynamic/"' not in html
    assert "/dynamic/" not in html
    assert "Runtime Review Workbench" not in html
    assert "Frida Hook 复核示例" not in html
    assert "不接入核心 scan_apk pipeline" not in html
    assert "静态 finding → Hook 点 → Runtime observation" not in html
    assert "运行复核模拟" not in html
    assert "runtimeTimeline" not in html
    assert "Exhibit Map" not in html
    assert "Upload APK" not in html
    assert "Scan Upload" not in html


def test_demo_handler_serves_assets_and_rejects_removed_dynamic_page():
    handler_class = create_handler(ROOT)
    page_request = _FakeSocket(b"GET /dynamic/ HTTP/1.1\r\nHost: local\r\n\r\n")
    trace_request = _FakeSocket(b"GET /dynamic/runtime_trace_example.json HTTP/1.1\r\nHost: local\r\n\r\n")
    image_head_request = _FakeSocket(b"HEAD /assets/apk-cutaway.png HTTP/1.1\r\nHost: local\r\n\r\n")

    handler_class(page_request, ("127.0.0.1", 12345), object())
    handler_class(trace_request, ("127.0.0.1", 12345), object())
    handler_class(image_head_request, ("127.0.0.1", 12345), object())
    page_response = page_request.wfile.getvalue()
    trace_response = trace_request.wfile.getvalue()
    image_response = image_head_request.wfile.getvalue()

    assert b"HTTP/1.0 404 Not Found" in page_response
    assert b"not found" in page_response
    assert b"HTTP/1.0 404 Not Found" in trace_response
    assert b"Content-Type: application/json; charset=utf-8" in trace_response
    assert b"not found" in trace_response
    assert b"HTTP/1.0 200 OK" in image_response
    assert b"Content-Type: image/png" in image_response
    assert b"Content-Length: " in image_response
    assert image_response.endswith(b"\r\n\r\n")


def test_main_reports_port_conflict_without_traceback(monkeypatch, capsys):
    def fake_serve(host, port, repo_root):
        raise OSError(48, "Address already in use")

    monkeypatch.setattr(demo_web, "serve", fake_serve)

    result = demo_web.main(["--host", "127.0.0.1", "--port", "8000"])
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert "127.0.0.1:8000" in captured.err
    assert "端口已被占用" in captured.err
    assert "make demo-web PORT=8001" in captured.err
