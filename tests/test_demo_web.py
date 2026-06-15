from pathlib import Path
from io import BytesIO
import json

import pytest

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
    assert "动态验证小 Demo" in html
    assert "Frida Hook 复核示例" in html
    assert "不接入核心 scan_apk pipeline" in html
    assert "静态 finding → Hook 点 → Runtime observation" in html
    assert "运行复核模拟" in html
    assert "runtimeTimeline" in html
    assert "展品导览" in html
    assert "证据链" in html
    assert "数据集说明" in html
    assert "合成 Oracle" in html
    assert "外部 APK 语料" in html
    assert "HardenInspector Micro F1" in html
    assert "34 个评分 APK" in html
    assert "69 个回归测试" in html
    assert "/assets/apk-cutaway.png" in html
    assert "/api/samples" in html
    assert "/api/scan" in html
    assert "/api/scan-upload" in html
    assert "/api/metrics" in html
    assert "上传 APK" in html
    assert "扫描上传文件" in html
    assert "证据" in html
    assert "Exhibit Map" not in html
    assert "Upload APK" not in html
    assert "Scan Upload" not in html


def test_static_pages_demo_is_self_contained_and_separate_from_docs_home():
    demo_html = ROOT / "docs" / "demo" / "index.html"
    trace_json = ROOT / "docs" / "demo" / "runtime_trace_example.json"
    probe_js = ROOT / "docs" / "demo" / "runtime_probe.js"

    assert demo_html.exists()
    assert trace_json.exists()
    assert probe_js.exists()
    html = demo_html.read_text(encoding="utf-8")
    trace = json.loads(trace_json.read_text(encoding="utf-8"))
    probe = probe_js.read_text(encoding="utf-8")

    assert "HardenInspector 静态 Web Demo" in html
    assert "动态验证小 Demo" in html
    assert "Frida Hook 复核示例" in html
    assert "不接入核心 scan_apk pipeline" in html
    assert "静态 finding → Hook 点 → Runtime observation" in html
    assert "运行复核模拟" in html
    assert "runtimeTimeline" in html
    assert "combined_hardened_showcase" in html
    assert "environment.debugger_probe" in html
    assert "System.getProperty" in html
    assert "Debug.isDebuggerConnected" in html
    assert "ClassLoader.loadClass" in html
    assert "dlopen" in html
    assert "runtime_trace_example.json" in html
    assert "runtime_probe.js" in html
    assert "/api/scan" not in html
    assert "/api/samples" not in html
    assert "扫描上传文件" not in html
    assert trace["scenario"] == "combined_hardened_showcase_dynamic_review"
    assert {event["hook"] for event in trace["events"]} >= {
        "System.getProperty",
        "Debug.isDebuggerConnected",
        "ClassLoader.loadClass",
        "dlopen",
    }
    assert any(event["static_finding"] == "environment.debugger_probe" for event in trace["events"])
    assert "Java.perform" in probe
    assert "System.getProperty" in probe
    assert "Debug.isDebuggerConnected" in probe
    assert "ClassLoader.loadClass" in probe
    assert "Interceptor.attach" in probe
    assert "android_dlopen_ext" in probe


def test_demo_asset_head_request_returns_png_headers_without_body():
    handler_class = create_handler(ROOT)
    request = _FakeSocket(b"HEAD /assets/apk-cutaway.png HTTP/1.1\r\nHost: local\r\n\r\n")

    handler_class(request, ("127.0.0.1", 12345), object())
    response = request.wfile.getvalue()

    assert b"HTTP/1.0 200 OK" in response
    assert b"Content-Type: image/png" in response
    assert b"Content-Length: " in response
    assert response.endswith(b"\r\n\r\n")
