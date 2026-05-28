from pathlib import Path

from hardeninspector.demo_web import (
    build_demo_catalog,
    load_demo_metrics,
    render_index_html,
    scan_demo_sample,
)


ROOT = Path(__file__).resolve().parents[1]


def test_demo_catalog_points_to_existing_curated_samples():
    catalog = build_demo_catalog(ROOT)
    by_id = {sample["id"]: sample for sample in catalog}

    assert {"fdroid_clean_baseline", "combined_hardened_showcase", "pivaa"} <= by_id.keys()
    assert len(catalog) >= 5
    for sample in catalog:
        apk_path = Path(sample["apk_path"])
        assert apk_path.exists()
        assert apk_path.suffix == ".apk"
        assert sample["size_bytes"] > 0


def test_scan_demo_sample_returns_report_with_expected_signal():
    result = scan_demo_sample("combined_hardened_showcase", ROOT)

    assert result["sample"]["id"] == "combined_hardened_showcase"
    assert result["report"]["summary"]["packer"] > 0
    assert result["report"]["summary"]["environment"] > 0
    assert result["report"]["findings"]
    assert any(finding["evidence"] for finding in result["report"]["findings"])


def test_load_demo_metrics_exposes_comparison_rows():
    metrics = load_demo_metrics(ROOT)
    rows = {(row["tool"], row["category"]): row for row in metrics["rows"]}

    assert set(metrics["tools"]) == {
        "hardeninspector",
        "apkid",
        "androguard_dex",
        "zip_string_baseline",
    }
    assert rows[("hardeninspector", "micro")]["f1"] == 0.987013
    assert rows[("apkid", "micro")]["f1"] < rows[("hardeninspector", "micro")]["f1"]


def test_render_index_html_contains_demo_api_surface():
    html = render_index_html()

    assert "HardenInspector Demo" in html
    assert "/api/samples" in html
    assert "/api/scan" in html
    assert "/api/metrics" in html
    assert "Evidence" in html
