"""Small local web demo for HardenInspector.

The demo intentionally uses only the Python standard library so it can run in a
fresh course-showcase environment after the package itself is installed.
"""

from __future__ import annotations

import argparse
import csv
import errno
import json
import sys
import tempfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .report import scan_apk


DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_METRICS_PATH = Path("reports/benchmark/benchmark_metrics.csv")
MAX_UPLOAD_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class DemoSample:
    id: str
    title: str
    source: str
    dataset_kind: str
    showcase_role: str
    apk_path: Path
    description: str
    expected_categories: tuple[str, ...]

    def to_dict(self, repo_root: Path) -> dict[str, Any]:
        path = repo_root / self.apk_path
        return {
            "id": self.id,
            "title": self.title,
            "source": self.source,
            "dataset_kind": self.dataset_kind,
            "showcase_role": self.showcase_role,
            "apk_path": str(path),
            "relative_path": str(self.apk_path),
            "description": self.description,
            "expected_categories": list(self.expected_categories),
            "size_bytes": path.stat().st_size,
        }


DEMO_SAMPLES = (
    DemoSample(
        id="fdroid_clean_baseline",
        title="F-Droid 合成干净基线",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="低噪声基线",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/fdroid_clean_baseline.apk"),
        description="良性基线样本，用来展示检测器可以输出空 finding，避免把正常 APK 误判为加固。",
        expected_categories=(),
    ),
    DemoSample(
        id="combined_hardened_showcase",
        title="综合加固展示样本",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="四类证据链样本",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk"),
        description="把加壳、混淆、环境探测和 Native 证据放在一个小样本里，适合现场完整演示。",
        expected_categories=("packer", "obfuscation", "environment", "native"),
    ),
    DemoSample(
        id="native_ptrace_loader",
        title="Native ptrace 与 loader 信号",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="ELF 符号证据",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/native_ptrace_loader.apk"),
        description="聚焦 Native 符号的样本，用来展示反调试和动态加载相关证据。",
        expected_categories=("environment", "native"),
    ),
    DemoSample(
        id="emulator_imei_probe",
        title="模拟器 IMEI 探测",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="环境探测证据",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/emulator_imei_probe.apk"),
        description="包含模拟器电话标识符的环境检测样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="java_debug_api_probe",
        title="Java Debug API 探测",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="Java 层反调试 API",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/java_debug_api_probe.apk"),
        description="使用 android.os.Debug 与 waitingForDebugger 证据的 Java 层反调试样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="adb_developer_settings_probe",
        title="ADB 与开发者设置探测",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="ADB 与开发者设置探测",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/adb_developer_settings_probe.apk"),
        description="检查 ADB_ENABLED、development_settings_enabled 等 Android Settings 键的环境探测样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="installer_source_probe",
        title="安装来源探测",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="安装来源环境探测",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/installer_source_probe.apk"),
        description="检查安装来源 API、侧载和 package-installer 指示器的环境探测样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="signature_integrity_check",
        title="签名完整性检查",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="签名完整性与防篡改证据",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/signature_integrity_check.apk"),
        description="把 PackageManager 签名 API 与 digest 证据结合起来的自完整性样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="root_artifact_probe",
        title="Root 痕迹探测",
        source="合成 Oracle",
        dataset_kind="合成 Oracle",
        showcase_role="Root 环境探测",
        apk_path=Path("datasets/hardeninspector_eval_v1/apks/root_artifact_probe.apk"),
        description="包含 su 路径、Superuser/Magisk 包名和 test-keys 证据的 Root 检测样本。",
        expected_categories=("environment",),
    ),
    DemoSample(
        id="pivaa",
        title="PIVAA 训练 APK",
        source="外部 APK 语料",
        dataset_kind="外部 APK 语料",
        showcase_role="真实 APK 解析检查",
        apk_path=Path("datasets/external_apk_corpus_v1/apks/security/pivaa.apk"),
        description="公开的 Android 漏洞训练应用，用来验证真实 APK 解析路径。",
        expected_categories=("packer", "obfuscation", "environment", "native"),
    ),
    DemoSample(
        id="fdroid_editor",
        title="F-Droid 编辑器 APK",
        source="外部 APK 语料",
        dataset_kind="外部 APK 语料",
        showcase_role="真实应用干净基线",
        apk_path=Path("datasets/external_apk_corpus_v1/apks/fdroid/org.billthefarmer.editor_198.apk"),
        description="真实开源 APK 基线，用来展示正常应用上的低噪声表现。",
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


def scan_uploaded_apk(
    apk_bytes: bytes,
    filename: str,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> dict[str, Any]:
    safe_name = Path(filename or "uploaded.apk").name or "uploaded.apk"
    if not safe_name.lower().endswith(".apk"):
        raise ValueError("上传文件必须是 APK")
    if not apk_bytes:
        raise ValueError("上传的 APK 为空")
    if len(apk_bytes) > max_bytes:
        raise ValueError(f"上传 APK 超过 {max_bytes // (1024 * 1024)} MiB 演示上限")

    with tempfile.TemporaryDirectory(prefix="hardeninspector-upload-") as tmp_dir:
        apk_path = Path(tmp_dir) / safe_name
        apk_path.write_bytes(apk_bytes)
        try:
            report = scan_apk(apk_path).to_dict()
        except Exception as exc:
            raise ValueError(f"上传 APK 无法扫描：{exc}") from exc

    report["apk"]["path"] = f"uploaded:{safe_name}"
    return {
        "sample": {
            "id": "uploaded",
            "title": safe_name,
            "source": "本地上传 APK",
            "dataset_kind": "本地上传文件",
            "showcase_role": "现场扫描验证",
            "apk_path": f"uploaded:{safe_name}",
            "relative_path": safe_name,
            "description": "通过本地演示页面上传，并在临时目录中完成扫描的 APK。",
            "expected_categories": [],
            "size_bytes": len(apk_bytes),
        },
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
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HardenInspector 本地演示</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --panel: #ffffff;
      --ink: #1a222b;
      --muted: #5e6b78;
      --faint: #8a95a0;
      --line: #d8dfe6;
      --line-soft: #e7ecf1;
      --accent: #0f766e;
      --accent-soft: #e6f2f0;
      --accent-ink: #0a4f49;
      --orange: #b7410e;
      --blue: #345995;
      --warn: #9b5c00;
      --code: #111827;
      --shadow: 0 1px 2px rgba(16, 24, 32, .04), 0 6px 16px rgba(16, 24, 32, .05);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.6 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", "Microsoft YaHei", sans-serif;
    }
    .wrap { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }

    /* Header */
    header {
      background: var(--panel);
      border-bottom: 1px solid var(--line);
    }
    .topbar { padding: 22px 0 20px; }
    .topbar-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 16px;
      flex-wrap: wrap;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-mark {
      width: 40px; height: 40px;
      border-radius: 10px;
      background: var(--accent);
      color: #fff;
      display: grid; place-items: center;
      font-weight: 800; font-size: 17px;
      flex-shrink: 0;
    }
    h1 { margin: 0; font-size: 24px; line-height: 1.15; letter-spacing: 0; }
    h2 { margin: 0; font-size: 17px; }
    h3 { margin: 0 0 6px; font-size: 15px; }
    p { margin: 6px 0; }
    button, input { font: inherit; }
    a { color: var(--accent); font-weight: 700; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .subtitle { color: var(--muted); max-width: 780px; font-size: 15px; margin-top: 4px; }
    .api-meta {
      color: var(--faint);
      font-size: 12px;
      line-height: 1.7;
      text-align: right;
    }
    .api-meta code {
      color: var(--accent);
      background: var(--accent-soft);
      padding: 1px 6px;
      border-radius: 4px;
      margin-left: 4px;
      white-space: nowrap;
      font-weight: 600;
    }

    /* Primary action bar — keeps the main flow front and center */
    .actionbar {
      background: var(--accent-soft);
      border-bottom: 1px solid var(--line);
    }
    .actionbar .wrap {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px 18px;
      padding: 14px 0;
    }
    .actionbar-title {
      font-weight: 700;
      color: var(--accent-ink);
      font-size: 14px;
    }
    .actionbar a {
      color: var(--accent-ink);
      font-size: 13px;
      font-weight: 600;
    }
    .actionbar-sep {
      width: 1px; height: 14px;
      background: var(--line);
    }

    /* Layout */
    main {
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 18px;
      padding: 20px 0 40px;
      align-items: start;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel);
      overflow: hidden;
      box-shadow: var(--shadow);
    }
    .toolbar {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 13px 15px;
      border-bottom: 1px solid var(--line-soft);
      background: #fbfcfd;
    }
    .content { padding: 15px; }

    /* Sample list */
    .sample-list { display: grid; gap: 6px; padding: 10px; }
    .sample-button {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: var(--ink);
      padding: 9px 11px;
      text-align: left;
      cursor: pointer;
      transition: border-color .12s, box-shadow .12s;
    }
    .sample-button:hover { border-color: var(--accent); }
    .sample-button:hover .sample-desc { display: block; }
    .sample-button.active {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }
    .sample-button.active .sample-desc { display: block; }
    .sample-title { display: block; font-weight: 700; margin-bottom: 2px; font-size: 14px; }
    .sample-desc {
      display: none;
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }
    .muted { color: var(--muted); font-size: 13px; }
    .faint { color: var(--faint); font-size: 12px; }
    .badge-row { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
    .badge {
      display: inline-flex;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 1px 7px;
      background: var(--panel);
      color: var(--muted);
      font-size: 11px;
      font-weight: 600;
    }
    .category-packer { color: var(--orange); border-color: rgba(183, 65, 14, .3); background: rgba(183, 65, 14, .04); }
    .category-obfuscation { color: var(--blue); border-color: rgba(52, 89, 149, .3); background: rgba(52, 89, 149, .04); }
    .category-environment { color: var(--warn); border-color: rgba(155, 92, 0, .3); background: rgba(155, 92, 0, .04); }
    .category-native { color: var(--accent); border-color: rgba(15, 118, 110, .3); background: rgba(15, 118, 110, .04); }

    /* Summary cards */
    .cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
    .card {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 12px;
    }
    .card .label { color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: .02em; }
    .card .value { font-size: 26px; font-weight: 700; line-height: 1.1; margin-top: 4px; }
    .card.has-value { border-color: var(--accent); background: var(--accent-soft); }
    .card.has-value .value { color: var(--accent-ink); }

    /* Findings */
    .finding {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fff;
      margin-top: 10px;
    }
    .finding-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
    .finding-id { color: var(--faint); font-size: 12px; margin-top: 2px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
    th, td { border-top: 1px solid var(--line-soft); padding: 7px 6px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--muted); font-weight: 600; font-size: 12px; }

    /* Buttons */
    .primary-button {
      min-height: 38px;
      border: 1px solid var(--accent);
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      padding: 8px 16px;
      cursor: pointer;
      font-weight: 700;
      transition: background .12s;
    }
    .primary-button:hover:not(:disabled) { background: var(--accent-ink); }
    .primary-button:disabled { opacity: .5; cursor: not-allowed; }

    /* Upload card */
    .upload-card {
      border: 1px dashed var(--line);
      border-radius: 10px;
      background: #fbfcfd;
      padding: 16px;
    }
    .upload-card.has-file { border-style: solid; border-color: var(--accent); background: var(--accent-soft); }
    .action-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }

    /* APK sources */
    .sources-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .sources-grid.sidebar { grid-template-columns: 1fr; }
    .source-item {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 11px 12px;
      display: flex;
      flex-direction: column;
      gap: 3px;
    }
    .source-item a { font-size: 14px; }
    .source-item .faint { line-height: 1.45; }

    /* Story strip */
    .story-strip {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .story-item {
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      background: #fbfcfd;
      padding: 11px 12px;
    }
    .story-item strong { font-size: 13px; }
    .story-item p { margin: 4px 0 0; }

    .empty {
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: #fbfcfd;
      color: var(--muted);
      padding: 18px;
      text-align: center;
    }
    .section-gap { margin-top: 18px; }
    .cutaway {
      width: 100%;
      max-height: 200px;
      object-fit: contain;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      margin-top: 14px;
    }

    footer {
      padding: 20px 0 30px;
      color: var(--faint);
      font-size: 12px;
      text-align: center;
    }

    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; }
      .topbar-row { flex-direction: column; }
      .api-meta { text-align: left; }
      .cards, .story-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 560px) {
      .cards, .story-strip, .sources-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap topbar">
      <div class="topbar-row">
        <div class="brand">
          <div class="brand-mark">HI</div>
          <div>
            <h1>HardenInspector 本地演示</h1>
            <p class="subtitle">选一个样本 APK 或上传你自己的 APK，本地扫描后会列出加固、混淆、环境检测等证据。</p>
          </div>
        </div>
        <div class="api-meta">
          Demo API
          <div><code>/api/samples</code><code>/api/scan</code></div>
          <div><code>/api/scan-upload</code><code>/api/metrics</code></div>
        </div>
      </div>
    </div>
  </header>

  <main class="wrap">
    <aside class="panel">
      <div class="toolbar">
        <h2>展品导览</h2>
        <span class="muted" id="sampleCount">加载中</span>
      </div>
      <div class="sample-list" id="sampleList"></div>
    </aside>

    <section>
      <div class="panel">
        <div class="toolbar">
          <div>
            <h2 id="selectedTitle">证据链</h2>
            <div class="muted" id="selectedMeta">选择样本后点击扫描</div>
          </div>
          <button class="primary-button" id="scanButton" type="button" disabled>扫描</button>
        </div>
        <div class="content">
          <div id="scanContent" class="empty">选择左侧样本后点「扫描」；或上传你自己的 APK。</div>

          <div class="upload-card section-gap" id="uploadCard">
            <h3>上传 APK</h3>
            <p class="muted" style="margin-top:0">没有合适的样本？上传你自己的 APK 文件，在本地走同一条扫描流程。</p>
            <div class="action-row">
              <input id="uploadFile" type="file" accept=".apk,application/vnd.android.package-archive">
              <button class="primary-button" id="uploadButton" type="button" disabled>扫描上传文件</button>
              <span class="muted" id="uploadMeta">未选择文件</span>
            </div>
          </div>
        </div>
      </div>

      <div class="panel section-gap">
        <div class="toolbar">
          <h2>找不到 APK？这些地方可以下</h2>
        </div>
        <div class="content">
          <div class="sources-grid" id="sourcesGrid"></div>
          <p class="faint" style="margin-top:10px">下载后建议用 <code>shasum -a 256 xxx.apk</code> 核对完整性，再上传到上方扫描区。</p>
        </div>
      </div>

      <div class="panel section-gap">
        <div class="toolbar">
          <h2>项目背景</h2>
        </div>
        <div class="content">
          <div class="story-strip">
            <div class="story-item">
              <strong>数据集说明</strong>
              <p class="muted">合成 Oracle 用来验证规则覆盖；外部 APK 语料用来展示真实解析路径。</p>
            </div>
            <div class="story-item">
              <strong>HardenInspector Micro F1</strong>
              <p class="muted">34 个评分 APK 上的 micro/macro 指标来自 reports/benchmark。</p>
            </div>
            <div class="story-item">
              <strong>71 个回归测试</strong>
              <p class="muted">覆盖样本生成、规则、CLI、Web Demo 和最终交付材料一致性。</p>
            </div>
          </div>
          <img class="cutaway" src="/assets/apk-cutaway.png" alt="APK 静态分析剖视图">
        </div>
      </div>

      <div class="panel section-gap">
        <div class="toolbar">
          <h2>Benchmark 摘要</h2>
          <span class="muted">34 个评分 APK</span>
        </div>
        <div class="content" id="metricsContent"></div>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrap">HardenInspector · 静态加固证据链检测器 · 本地演示不会上传你的 APK 到任何外部服务器</div>
  </footer>

  <script>
    const state = { samples: [], selected: null, scanning: false, uploadFile: null };
    const categories = ["packer", "obfuscation", "environment", "native"];
    const categoryLabels = {
      packer: "加壳",
      obfuscation: "混淆",
      environment: "环境检测",
      native: "Native",
      clean: "无 finding",
      micro: "Micro 汇总",
      macro: "Macro 汇总"
    };
    const severityLabels = { low: "低", medium: "中", high: "高" };
    const confidenceLabels = { low: "低", medium: "中", high: "高" };

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[ch]));
    }
    function categoryLabel(value) {
      return categoryLabels[value] || value;
    }
    function renderSamples() {
      const container = document.getElementById("sampleList");
      document.getElementById("sampleCount").textContent = `${state.samples.length} 个 APK`;
      container.innerHTML = state.samples.map(sample => `
        <button class="sample-button ${state.selected?.id === sample.id ? "active" : ""}" data-id="${escapeHtml(sample.id)}">
          <span class="sample-title">${escapeHtml(sample.title)}</span>
          <span class="muted">${escapeHtml(sample.dataset_kind)} · ${(sample.size_bytes / 1024).toFixed(1)} KB</span>
          <span class="sample-desc">${escapeHtml(sample.description)}</span>
          <span class="badge-row">
            ${(sample.expected_categories && sample.expected_categories.length ? sample.expected_categories : ["clean"]).map(category => `
              <span class="badge category-${escapeHtml(category)}">${escapeHtml(categoryLabel(category))}</span>
            `).join("")}
          </span>
        </button>
      `).join("");
      container.querySelectorAll("button").forEach(button => {
        button.addEventListener("click", () => selectSample(button.dataset.id));
      });
    }
    function selectSample(id) {
      state.selected = state.samples.find(sample => sample.id === id) || null;
      document.getElementById("scanButton").disabled = !state.selected;
      if (!state.selected) return;
      document.getElementById("selectedTitle").textContent = state.selected.title;
      document.getElementById("selectedMeta").textContent = `${state.selected.dataset_kind} · ${state.selected.showcase_role} · ${state.selected.relative_path}`;
      document.getElementById("scanContent").className = "section-gap empty";
      document.getElementById("scanContent").innerHTML = `已选择 <strong>${escapeHtml(state.selected.title)}</strong>，点上面的「扫描」开始。`;
      renderSamples();
    }
    function renderReport(result) {
      const report = result.report || {};
      const summary = report.summary || {};
      const cards = categories.map(category => {
        const count = summary[category] || 0;
        return `
          <div class="card ${count > 0 ? "has-value" : ""}">
            <div class="label">${escapeHtml(categoryLabel(category))}</div>
            <div class="value">${count}</div>
          </div>
        `;
      }).join("");
      const findings = (report.findings || []).length ? report.findings.map(finding => `
        <article class="finding">
          <div class="finding-head">
            <div>
              <strong>${escapeHtml(finding.title)}</strong>
              <div class="finding-id">${escapeHtml(finding.id)}</div>
            </div>
            <span class="badge category-${escapeHtml(finding.category)}">${escapeHtml(categoryLabel(finding.category))}</span>
          </div>
          <div class="muted" style="margin-top:4px">严重度 ${escapeHtml(severityLabels[finding.severity] || finding.severity)} · 置信度 ${escapeHtml(confidenceLabels[finding.confidence] || finding.confidence)}</div>
          <table>
            <thead><tr><th>证据</th><th>取值</th><th>位置</th></tr></thead>
            <tbody>
              ${(finding.evidence || []).slice(0, 8).map(item => `
                <tr><td>${escapeHtml(item.kind)}</td><td>${escapeHtml(item.value)}</td><td>${escapeHtml(item.location)}</td></tr>
              `).join("")}
            </tbody>
          </table>
        </article>
      `).join("") : `<div class="empty">这个样本没有命中加固或反分析证据。</div>`;
      document.getElementById("scanContent").className = "section-gap";
      document.getElementById("scanContent").innerHTML = `
        <div class="cards">${cards}</div>
        <p style="margin-top:0">${escapeHtml(result.sample?.description || "")}</p>
        <div class="muted" style="font-size:12px">SHA-256: ${escapeHtml(report.apk?.sha256 || "")}<br>ZIP entries: ${escapeHtml(report.apk?.entry_count || "")}</div>
        ${findings}
      `;
    }
    async function scanSelected() {
      if (!state.selected || state.scanning) return;
      state.scanning = true;
      const button = document.getElementById("scanButton");
      button.disabled = true;
      button.textContent = "扫描中…";
      document.getElementById("scanContent").className = "section-gap empty";
      document.getElementById("scanContent").innerHTML = "正在解析 APK 并提取证据…";
      try {
        const response = await fetch(`/api/scan?id=${encodeURIComponent(state.selected.id)}`);
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "扫描失败");
        renderReport(result);
      } catch (error) {
        document.getElementById("scanContent").innerHTML = escapeHtml(error.message);
      } finally {
        state.scanning = false;
        button.disabled = false;
        button.textContent = "扫描";
      }
    }
    async function scanUpload() {
      if (!state.uploadFile || state.scanning) return;
      state.scanning = true;
      const button = document.getElementById("uploadButton");
      button.disabled = true;
      button.textContent = "扫描中…";
      document.getElementById("selectedTitle").textContent = state.uploadFile.name;
      document.getElementById("selectedMeta").textContent = `本地上传 APK · ${(state.uploadFile.size / 1024).toFixed(1)} KB`;
      document.getElementById("scanContent").className = "section-gap empty";
      document.getElementById("scanContent").innerHTML = "正在扫描上传的 APK…";
      try {
        const response = await fetch(`/api/scan-upload?filename=${encodeURIComponent(state.uploadFile.name)}`, {
          method: "POST",
          headers: { "Content-Type": "application/vnd.android.package-archive" },
          body: state.uploadFile
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "上传扫描失败");
        renderReport(result);
      } catch (error) {
        document.getElementById("scanContent").innerHTML = escapeHtml(error.message);
      } finally {
        state.scanning = false;
        button.disabled = false;
        button.textContent = "扫描上传文件";
      }
    }
    const apkSources = [
      { name: "F-Droid（开源应用商店）", url: "https://f-droid.org/", note: "干净的开源 APK，适合做良性基线。" },
      { name: "APKPure", url: "https://apkpure.com/", note: "按地区/版本抓取 Play Store 应用的 APK。" },
      { name: "DroidBench", url: "https://github.com/secure-software-engineering/DroidBench", note: "学术界常用的 Android 漏洞基准测试集。" },
      { name: "PIVAA", url: "https://github.com/nowdb/PIVAA", note: "公开的 Android 漏洞训练应用。" },
      { name: "Android 官方 Sample", url: "https://android.googlesource.com/platform/development/+/master/samples/", note: "Google 提供的官方示例应用。" },
      { name: "APKMirror", url: "https://apkmirror.com/", note: "收录历史版本的 APK 镜像站。" }
    ];
    function renderSources() {
      document.getElementById("sourcesGrid").innerHTML = apkSources.map(src => `
        <div class="source-item">
          <a href="${escapeHtml(src.url)}" target="_blank" rel="noopener">${escapeHtml(src.name)}</a>
          <span class="faint">${escapeHtml(src.note)}</span>
        </div>
      `).join("");
    }
    function renderMetrics(metrics) {
      const rows = (metrics.rows || []).filter(row => row.category === "micro" || row.category === "macro");
      document.getElementById("metricsContent").innerHTML = `
        <table>
          <thead><tr><th>工具</th><th>行</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
          <tbody>
            ${rows.map(row => `
              <tr>
                <td>${escapeHtml(row.tool)}</td>
                <td>${escapeHtml(categoryLabel(row.category))}</td>
                <td>${Number(row.precision ?? 0).toFixed(3)}</td>
                <td>${Number(row.recall ?? 0).toFixed(3)}</td>
                <td>${Number(row.f1 ?? 0).toFixed(3)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    }
    async function init() {
      renderSources();
      const [samplesResponse, metricsResponse] = await Promise.all([
        fetch("/api/samples"),
        fetch("/api/metrics")
      ]);
      const samplePayload = await samplesResponse.json();
      state.samples = samplePayload.samples || [];
      renderSamples();
      if (state.samples.length) selectSample(state.samples[0].id);
      renderMetrics(await metricsResponse.json());
    }
    document.getElementById("scanButton").addEventListener("click", scanSelected);
    document.getElementById("uploadFile").addEventListener("change", event => {
      state.uploadFile = event.target.files?.[0] || null;
      document.getElementById("uploadButton").disabled = !state.uploadFile;
      document.getElementById("uploadCard").classList.toggle("has-file", !!state.uploadFile);
      document.getElementById("uploadMeta").textContent = state.uploadFile
        ? `${state.uploadFile.name} · ${(state.uploadFile.size / 1024).toFixed(1)} KB`
        : "未选择文件";
    });
    document.getElementById("uploadButton").addEventListener("click", scanUpload);
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
            self._handle_read_request(include_body=True)

        def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._handle_read_request(include_body=False)

        def _handle_read_request(self, include_body: bool) -> None:
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/":
                    self._send_text(render_index_html(), "text/html; charset=utf-8", include_body=include_body)
                elif parsed.path == "/assets/apk-cutaway.png":
                    self._send_file(
                        root / "slides/figures/apk_static_analysis_cutaway.png",
                        "image/png",
                        include_body=include_body,
                    )
                elif parsed.path == "/api/samples":
                    self._send_json({"samples": build_demo_catalog(root)}, include_body=include_body)
                elif parsed.path == "/api/scan":
                    query = parse_qs(parsed.query)
                    sample_id = query.get("id", [""])[0]
                    if not sample_id:
                        self._send_json({"error": "missing sample id"}, HTTPStatus.BAD_REQUEST, include_body=include_body)
                    else:
                        self._send_json(scan_demo_sample(sample_id, root), include_body=include_body)
                elif parsed.path == "/api/metrics":
                    self._send_json(load_demo_metrics(root), include_body=include_body)
                else:
                    self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND, include_body=include_body)
            except KeyError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND, include_body=include_body)
            except Exception as exc:  # pragma: no cover - defensive server boundary
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR, include_body=include_body)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            parsed = urlparse(self.path)
            if parsed.path != "/api/scan-upload":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json({"error": "invalid content length"}, HTTPStatus.BAD_REQUEST)
                return
            if content_length > MAX_UPLOAD_BYTES:
                self._send_json(
                    {"error": f"上传 APK 超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB 演示上限"},
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                return

            query = parse_qs(parsed.query)
            filename = query.get("filename", ["uploaded.apk"])[0]
            try:
                body = self.rfile.read(content_length)
                self._send_json(scan_uploaded_apk(body, filename))
            except ValueError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:  # pragma: no cover - defensive server boundary
                self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(
            self,
            payload: dict[str, Any],
            status: HTTPStatus = HTTPStatus.OK,
            include_body: bool = True,
        ) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def _send_text(
            self,
            text: str,
            content_type: str,
            status: HTTPStatus = HTTPStatus.OK,
            include_body: bool = True,
        ) -> None:
            body = text.encode("utf-8")
            self.send_response(status.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if include_body:
                self.wfile.write(body)

        def _send_file(self, path: Path, content_type: str, include_body: bool = True) -> None:
            if not path.exists() or not path.is_file():
                self._send_json({"error": "asset not found"}, HTTPStatus.NOT_FOUND, include_body=include_body)
                return
            body = path.read_bytes()
            self.send_response(HTTPStatus.OK.value)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if include_body:
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

    try:
        server = serve(args.host, args.port, args.repo_root)
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            raise
        print(f"错误：{args.host}:{args.port} 端口已被占用。", file=sys.stderr)
        print("请关闭占用该端口的进程，或改用其他端口：make demo-web PORT=8001", file=sys.stderr)
        return 1

    print(f"HardenInspector 本地演示: http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止 HardenInspector 本地演示。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
