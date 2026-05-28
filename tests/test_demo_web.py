from pathlib import Path
from io import BytesIO

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
        "signature_integrity_check",
        "pivaa",
    } <= by_id.keys()
    assert len(catalog) >= 5
    for sample in catalog:
        apk_path = Path(sample["apk_path"])
        assert apk_path.exists()
        assert apk_path.suffix == ".apk"
        assert sample["size_bytes"] > 0
        assert sample["dataset_kind"] in {"Synthetic oracle", "External corpus"}
        assert sample["showcase_role"]

    assert by_id["combined_hardened_showcase"]["showcase_role"] == "All-category evidence chain"
    assert by_id["signature_integrity_check"]["showcase_role"] == "Anti-tamper integrity evidence"
    assert by_id["fdroid_editor"]["dataset_kind"] == "External corpus"


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
    assert result["sample"]["source"] == "Uploaded APK"
    assert result["sample"]["size_bytes"] == apk_path.stat().st_size
    assert result["report"]["summary"]["packer"] > 0
    assert result["report"]["summary"]["environment"] > 0


def test_scan_uploaded_apk_rejects_non_apk_and_oversized_inputs():
    with pytest.raises(ValueError, match="APK file"):
        scan_uploaded_apk(b"not an apk", "notes.txt")

    with pytest.raises(ValueError, match="exceeds"):
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

    assert "HardenInspector Demo" in html
    assert "Exhibit Map" in html
    assert "Evidence Chain" in html
    assert "Dataset Story" in html
    assert "Synthetic Oracle" in html
    assert "External APK Corpus" in html
    assert "HardenInspector Micro F1" in html
    assert "30 scored APKs" in html
    assert "50 regression tests" in html
    assert "/assets/apk-cutaway.png" in html
    assert "/api/samples" in html
    assert "/api/scan" in html
    assert "/api/scan-upload" in html
    assert "/api/metrics" in html
    assert "Upload APK" in html
    assert "Evidence" in html


def test_demo_asset_head_request_returns_png_headers_without_body():
    handler_class = create_handler(ROOT)
    request = _FakeSocket(b"HEAD /assets/apk-cutaway.png HTTP/1.1\r\nHost: local\r\n\r\n")

    handler_class(request, ("127.0.0.1", 12345), object())
    response = request.wfile.getvalue()

    assert b"HTTP/1.0 200 OK" in response
    assert b"Content-Type: image/png" in response
    assert b"Content-Length: " in response
    assert response.endswith(b"\r\n\r\n")
