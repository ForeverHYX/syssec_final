"""Small local web demo for HardenInspector.

The demo intentionally uses only the Python standard library so it can run in a
fresh course-showcase environment after the package itself is installed.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .report import scan_apk


DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_METRICS_PATH = Path("reports/benchmark/benchmark_metrics.csv")


@dataclass(frozen=True)
class DemoSample:
    id: str
    title: str
    source: str
    apk_path: Path
    description: str
    expected_categories: tuple[str, ...]

    def to_dict(self, repo_root: Path) -> dict[str, Any]:
        path = repo_root / self.apk_path
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "apk_path": str(path),
            "relative_path": str(self.apk_path),
            "description": self.description,
            "expected_categories": list(self.expected_categories),
            "size_bytes": path.stat().st_size,
        }


DEMO_SAMPLES = (
    DemoSample(
        id="fdroid_clean_baseline",
        title="F-Droid clean synthetic baseline",
        source="Synthetic oracle",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/fdroid_clean_baseline.apk"),
        description="A benign baseline sample used to show that the detector can produce an empty finding set.",
        expected_categories=(),
    ),
    DemoSample(
        id="combined_hardened_showcase",
        title="Combined hardened showcase",
        source="Synthetic oracle",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk"),
        description="A compact exhibit sample combining packer, obfuscation, environment, and native indicators.",
        expected_categories=("packer", "obfuscation", "environment", "native"),
    ),
    DemoSample(
        id="native_ptrace_loader",
        title="Native ptrace and loader signals",
        source="Synthetic oracle",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/native_ptrace_loader.apk"),
        description="Native-symbol focused sample for anti-debug and dynamic loader evidence.",
        expected_categories=("environment", "native"),
    ),
    DemoSample(
        id="emulator_imei_probe",
        title="Emulator IMEI probe",
        source="Synthetic oracle",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/emulator_imei_probe.apk"),
        description="Environment-detection sample with emulator telephony identifiers.",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="pivaa",
        title="PIVAA training APK",
        source="External corpus",
        apk_path=Path("datasets/external_apk_corpus_v1/apks/security/pivaa.apk"),
        description="Public vulnerable Android app used as a real APK sanity check.",
        expected_categories=("packer", "obfuscation", "environment", "native"),
    ),
    DemoSample(
        id="fdroid_editor",
        title="F-Droid editor APK",
        source="External corpus",
        apk_path=Path("datasets/external_apk_corpus_v1/apks/fdroid/org.billthefarmer.editor_198.apk"),
        description="Real open-source APK baseline used to demonstrate low-noise behavior.",
        expected_categories=(),
    ),
)


def build_demo_catalog(repo_root: str | Path = DEFAULT_REPO_ROOT) -> list[dict[str, Any]]:
    root = Path(repo_root)
    catalog: list[dict[str, Any]] = []
    for sample in DEMO_SAMPLES:
        path = root / sample.apk_path
        if path.exists():
            catalog.append(sample.to_dict(root))
    return catalog


def _find_demo_sample(sample_id: str, repo_root: Path) -> DemoSample:
    for sample in DEMO_SAMPLES:
        path = repo_root / sample.apk_path
        if sample.id == sample_id and path.exists():
            return sample
    raise KeyError(f"unknown demo sample: {sample_id}")


def scan_demo_sample(sample_id: str, repo_root: str | Path = DEFAULT_REPO_ROOT) -> dict[str, Any]:
    root = Path(repo_root)
    sample = _find_demo_sample(sample_id, root)
    report = scan_apk(root / sample.apk_path).to_dict()
    return {
        "sample": sample.to_dict(root),
        "report": report,
    }


def load_demo_metrics(repo_root: str | Path = DEFAULT_REPO_ROOT) -> dict[str, Any]:
    root = Path(repo_root)
    metrics_path = root / BENCHMARK_METRICS_PATH
    rows: list[dict[str, Any]] = []
    tools: list[str] = []
    if not metrics_path.exists():
        return {"path": str(metrics_path), "tools": tools, "rows": rows}

    with metrics_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            parsed = {
                "tool": row["tool"],
                "category": row["category"],
                "tp": _parse_optional_int(row.get("tp", "")),
                "fp": _parse_optional_int(row.get("fp", "")),
                "fn": _parse_optional_int(row.get("fn", "")),
                "tn": _parse_optional_int(row.get("tn", "")),
                "precision": _parse_float(row.get("precision", "")),
                "recall": _parse_float(row.get("recall", "")),
                "f1": _parse_float(row.get("f1", "")),
            }
            rows.append(parsed)
            if parsed["tool"] not in tools:
                tools.append(parsed["tool"])

    return {"path": str(metrics_path), "tools": tools, "rows": rows}


def _parse_optional_int(value: str | None) -> int | None:
    if not value:
        return None
    return int(value)


def _parse_float(value: str | None) -> float | None:
    if not value:
        return None
    return float(value)


def render_index_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HardenInspector Demo</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f7f4;
      --panel: #ffffff;
      --ink: #1f2933;
      --muted: #65717f;
      --line: #d8ded8;
      --accent: #1b6b5f;
      --accent-2: #b7410e;
      --accent-3: #345995;
      --warn: #9b5c00;
      --shadow: 0 14px 30px rgba(31, 41, 51, 0.10);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      border-bottom: 1px solid var(--line);
      background: #fdfdfb;
    }
    .wrap {
      width: min(1180px, calc(100vw - 32px));
      margin: 0 auto;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 18px 0;
    }
    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 750;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 3px 0 0;
      color: var(--muted);
      font-size: 13px;
    }
    .api {
      color: var(--muted);
      font-size: 12px;
      text-align: right;
    }
    .api code {
      color: var(--accent);
      margin-left: 7px;
      white-space: nowrap;
    }
    main {
      display: grid;
      grid-template-columns: 330px minmax(0, 1fr);
      gap: 18px;
      padding: 18px 0 28px;
    }
    section, aside {
      min-width: 0;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .sample-list {
      display: grid;
      gap: 8px;
      padding: 12px;
    }
    .sample-button {
      border: 1px solid var(--line);
      background: #fbfbf9;
      color: var(--ink);
      border-radius: 8px;
      padding: 11px;
      text-align: left;
      cursor: pointer;
      min-height: 78px;
    }
    .sample-button:hover, .sample-button.active {
      border-color: var(--accent);
      outline: 2px solid rgba(27, 107, 95, 0.12);
    }
    .sample-title {
      display: block;
      font-weight: 700;
      margin-bottom: 3px;
    }
    .sample-meta, .muted {
      color: var(--muted);
      font-size: 12px;
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
    }
    .toolbar h2, .metrics h2 {
      margin: 0;
      font-size: 17px;
      letter-spacing: 0;
    }
    .scan-button {
      border: 0;
      border-radius: 7px;
      background: var(--accent);
      color: white;
      padding: 9px 13px;
      font-weight: 700;
      cursor: pointer;
      min-width: 92px;
    }
    .scan-button:disabled {
      opacity: .55;
      cursor: wait;
    }
    .content {
      padding: 16px;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }
    .card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      min-height: 80px;
      background: #fbfbf9;
    }
    .card .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
    }
    .card .value {
      font-size: 25px;
      font-weight: 800;
      margin-top: 4px;
    }
    .findings {
      display: grid;
      gap: 10px;
    }
    .finding {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: white;
    }
    .finding-head {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 6px;
    }
    .badge-row {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      border: 1px solid var(--line);
      padding: 2px 7px;
      color: var(--muted);
      background: #fafaf7;
      font-size: 12px;
    }
    .category-packer { color: var(--accent-2); border-color: rgba(183, 65, 14, .35); }
    .category-obfuscation { color: var(--accent-3); border-color: rgba(52, 89, 149, .35); }
    .category-environment { color: var(--warn); border-color: rgba(155, 92, 0, .35); }
    .category-native { color: var(--accent); border-color: rgba(27, 107, 95, .35); }
    .evidence {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 12px;
    }
    .evidence th, .evidence td {
      border-top: 1px solid var(--line);
      padding: 7px 6px;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    .metrics {
      margin-top: 18px;
      overflow: hidden;
    }
    .metrics .content {
      overflow-x: auto;
    }
    .metric-table {
      width: 100%;
      border-collapse: collapse;
      min-width: 720px;
    }
    .metric-table th, .metric-table td {
      border-bottom: 1px solid var(--line);
      padding: 8px;
      text-align: right;
      font-variant-numeric: tabular-nums;
    }
    .metric-table th:first-child,
    .metric-table th:nth-child(2),
    .metric-table td:first-child,
    .metric-table td:nth-child(2) {
      text-align: left;
    }
    .empty {
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 22px;
      color: var(--muted);
      text-align: center;
      background: #fbfbf9;
    }
    @media (max-width: 840px) {
      .topbar { align-items: flex-start; flex-direction: column; }
      .api { text-align: left; }
      main { grid-template-columns: 1fr; }
      .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div>
        <h1>HardenInspector Demo</h1>
        <p class="subtitle">Interactive local showcase for static Android hardening evidence.</p>
      </div>
      <div class="api">
        API <code>/api/samples</code><code>/api/scan?id=...</code><code>/api/metrics</code>
      </div>
    </div>
  </header>
  <main class="wrap">
    <aside class="panel">
      <div class="toolbar">
        <h2>Samples</h2>
        <span class="muted" id="sampleCount">Loading</span>
      </div>
      <div class="sample-list" id="sampleList"></div>
    </aside>
    <section>
      <div class="panel">
        <div class="toolbar">
          <div>
            <h2 id="selectedTitle">Select a sample</h2>
            <div class="muted" id="selectedMeta">APK scan results render here.</div>
          </div>
          <button class="scan-button" id="scanButton" disabled>Scan</button>
        </div>
        <div class="content" id="scanContent">
          <div class="empty">Choose a sample from the left panel, then scan it.</div>
        </div>
      </div>
      <div class="panel metrics">
        <div class="toolbar">
          <h2>Benchmark Comparison</h2>
          <span class="muted">Micro/macro and category rows from reports/benchmark</span>
        </div>
        <div class="content" id="metricsContent">
          <div class="empty">Loading metrics.</div>
        </div>
      </div>
    </section>
  </main>
  <script>
    const state = { samples: [], selected: null, scanning: false };
    const categories = ["packer", "obfuscation", "environment", "native"];

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[ch]));
    }

    function renderSamples() {
      const container = document.getElementById("sampleList");
      document.getElementById("sampleCount").textContent = `${state.samples.length} APKs`;
      container.innerHTML = state.samples.map(sample => `
        <button class="sample-button ${state.selected?.id === sample.id ? "active" : ""}" data-id="${escapeHtml(sample.id)}">
          <span class="sample-title">${escapeHtml(sample.title)}</span>
          <span class="sample-meta">${escapeHtml(sample.source)} · ${(sample.size_bytes / 1024).toFixed(1)} KB</span>
          <span class="sample-meta" style="display:block;margin-top:5px;">${escapeHtml(sample.description)}</span>
        </button>
      `).join("");
      container.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => selectSample(button.dataset.id));
      });
    }

    function selectSample(id) {
      state.selected = state.samples.find(sample => sample.id === id);
      document.getElementById("scanButton").disabled = !state.selected;
      document.getElementById("selectedTitle").textContent = state.selected.title;
      document.getElementById("selectedMeta").textContent = `${state.selected.relative_path}`;
      document.getElementById("scanContent").innerHTML = `
        <div class="empty">Ready to scan ${escapeHtml(state.selected.title)}.</div>
      `;
      renderSamples();
    }

    function renderReport(result) {
      const report = result.report;
      const summary = report.summary || {};
      const cards = categories.map(category => `
        <div class="card">
          <div class="label">${escapeHtml(category)}</div>
          <div class="value">${summary[category] || 0}</div>
        </div>
      `).join("");

      const findings = report.findings || [];
      const findingHtml = findings.length ? findings.map(finding => `
        <article class="finding">
          <div class="finding-head">
            <strong>${escapeHtml(finding.title)}</strong>
            <span class="badge category-${escapeHtml(finding.category)}">${escapeHtml(finding.category)}</span>
          </div>
          <div class="muted">${escapeHtml(finding.id)} · ${escapeHtml(finding.severity)} severity · ${escapeHtml(finding.confidence)} confidence</div>
          <div class="badge-row">
            ${(finding.evidence || []).slice(0, 8).map(item => `
              <span class="badge">${escapeHtml(item.kind)}</span>
            `).join("")}
          </div>
          <table class="evidence">
            <thead><tr><th>Evidence</th><th>Value</th><th>Location</th></tr></thead>
            <tbody>
              ${(finding.evidence || []).slice(0, 8).map(item => `
                <tr>
                  <td>${escapeHtml(item.kind)}</td>
                  <td>${escapeHtml(item.value)}</td>
                  <td>${escapeHtml(item.location)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </article>
      `).join("") : `<div class="empty">No hardening indicators matched this sample.</div>`;

      document.getElementById("scanContent").innerHTML = `
        <div class="cards">${cards}</div>
        <div class="muted">SHA-256: ${escapeHtml(report.apk.sha256)} · ZIP entries: ${report.apk.entry_count}</div>
        <div class="findings" style="margin-top:14px;">${findingHtml}</div>
      `;
    }

    async function scanSelected() {
      if (!state.selected || state.scanning) return;
      state.scanning = true;
      const button = document.getElementById("scanButton");
      button.disabled = true;
      button.textContent = "Scanning";
      document.getElementById("scanContent").innerHTML = `<div class="empty">Scanning APK and extracting evidence.</div>`;
      try {
        const response = await fetch(`/api/scan?id=${encodeURIComponent(state.selected.id)}`);
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Scan failed");
        renderReport(result);
      } catch (error) {
        document.getElementById("scanContent").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
      } finally {
        state.scanning = false;
        button.disabled = false;
        button.textContent = "Scan";
      }
    }

    function renderMetrics(metrics) {
      const rows = (metrics.rows || []).filter(row => row.category === "micro" || row.category === "macro");
      const body = rows.map(row => `
        <tr>
          <td>${escapeHtml(row.tool)}</td>
          <td>${escapeHtml(row.category)}</td>
          <td>${Number(row.precision ?? 0).toFixed(3)}</td>
          <td>${Number(row.recall ?? 0).toFixed(3)}</td>
          <td>${Number(row.f1 ?? 0).toFixed(3)}</td>
        </tr>
      `).join("");
      document.getElementById("metricsContent").innerHTML = `
        <table class="metric-table">
          <thead><tr><th>Tool</th><th>Row</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
          <tbody>${body}</tbody>
        </table>
      `;
    }

    async function init() {
      const [samplesResponse, metricsResponse] = await Promise.all([
        fetch("/api/samples"),
        fetch("/api/metrics")
      ]);
      const samplesPayload = await samplesResponse.json();
      state.samples = samplesPayload.samples || [];
      renderSamples();
      if (state.samples.length) selectSample(state.samples[0].id);
      renderMetrics(await metricsResponse.json());
    }

    document.getElementById("scanButton").addEventListener("click", scanSelected);
    init().catch(error => {
      document.getElementById("sampleList").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
    });
  </script>
</body>
</html>
"""


def create_handler(repo_root: str | Path = DEFAULT_REPO_ROOT) -> type[BaseHTTPRequestHandler]:
    root = Path(repo_root)

    class DemoRequestHandler(BaseHTTPRequestHandler):
        server_version = "HardenInspectorDemo/0.1"

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/":
                    self._send_text(render_index_html(), "text/html; charset=utf-8")
                elif parsed.path == "/api/samples":
                    self._send_json({"samples": build_demo_catalog(root)})
                elif parsed.path == "/api/scan":
                    query = parse_qs(parsed.query)
                    sample_id = query.get("id", [""])[0]
                    if not sample_id:
                        self._send_json({"error": "missing sample id"}, HTTPStatus.BAD_REQUEST)
                    else:
                        self._send_json(scan_demo_sample(sample_id, root))
                elif parsed.path == "/api/metrics":
                    self._send_json(load_demo_metrics(root))
                else:
                    self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except KeyError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except Exception as exc:  # pragma: no cover - defensive server boundary
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, text: str, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = text.encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return DemoRequestHandler


def serve(host: str, port: int, repo_root: str | Path = DEFAULT_REPO_ROOT) -> ThreadingHTTPServer:
    handler = create_handler(repo_root)
    return ThreadingHTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local HardenInspector web demo.")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind")
    parser.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT, help="Repository root for samples/reports")
    args = parser.parse_args(argv)

    server = serve(args.host, args.port, args.repo_root)
    print(f"HardenInspector Demo: http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping HardenInspector Demo.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
