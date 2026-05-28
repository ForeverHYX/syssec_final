# 本地 Web Demo

`demo-web` 是期末现场展示用的轻量网页。它不依赖 Flask、Node 或外部 CDN，只使用 Python 标准库启动本地 HTTP 服务，便于在教室网络不稳定时离线演示。

## 启动

```bash
make demo-web
```

默认地址：

```text
http://127.0.0.1:8000/
```

也可以直接指定端口：

```bash
.venv/bin/python -m hardeninspector.demo_web --host 127.0.0.1 --port 8765
```

## 页面内容

页面内置一组展示样本：

| 样本 | 作用 |
| --- | --- |
| `fdroid_clean_baseline` | 合成 clean baseline，展示无 finding 的低噪声结果 |
| `combined_hardened_showcase` | 综合展示 packer、obfuscation、environment、native 证据 |
| `native_ptrace_loader` | 展示 ELF 符号级 Native anti-debug / loader evidence |
| `emulator_imei_probe` | 展示 emulator telephony/device-id probe |
| `pivaa` | 外部现成 APK，用于证明真实 APK 也能扫描 |
| `fdroid_editor` | F-Droid 真实 APK baseline，用于展示正常样本低误报 |

扫描后页面展示四类 summary 计数、finding 列表和 evidence 表。Benchmark 区域直接读取 `reports/benchmark/benchmark_metrics.csv`，展示 HardenInspector 与 APKiD、Androguard DEX、ZIP Strings 的 micro/macro Precision、Recall、F1。

## API

页面使用三个本地接口：

| 接口 | 返回 |
| --- | --- |
| `/api/samples` | 可展示样本列表、路径、来源、说明和期望类别 |
| `/api/scan?id=<sample_id>` | 指定样本的 HardenInspector JSON report |
| `/api/metrics` | `reports/benchmark/benchmark_metrics.csv` 解析后的指标行 |

这些接口只读取仓库内已提交的 APK 和报告文件，不上传数据，也不需要联网。
