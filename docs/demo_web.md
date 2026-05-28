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

页面首屏现在按“最终成果展示”组织，而不是只给扫描按钮：

| 区域 | 说明 |
| --- | --- |
| Exhibit Map | 解释项目为什么存在：检测 APK 加固证据，而不是判恶意 |
| Evidence Chain | 强调 Manifest、DEX、Native 符号、资源和熵值如何汇总为 finding |
| Dataset Story | 直观区分 22 个 Synthetic Oracle APK 与 12 个 External APK Corpus |
| 指标摘要 | 展示 34 个评分 APK、69 个回归测试和 HardenInspector Micro F1 |
| APK 拆解图 | 使用 `slides/figures/apk_static_analysis_cutaway.png` 作为视觉说明 |

页面内置一组展示样本，每个样本都带有 dataset kind 和 showcase role，便于现场讲清楚“这个样本为什么在这里”：

| 样本 | 作用 |
| --- | --- |
| `fdroid_clean_baseline` | 合成 clean baseline，展示无 finding 的低噪声结果 |
| `combined_hardened_showcase` | 综合展示 packer、obfuscation、environment、native 证据 |
| `adb_developer_settings_probe` | 展示 Android Settings API 与 `ADB_ENABLED` / `development_settings_enabled` 组合形成的 ADB/developer-settings environment evidence |
| `installer_source_probe` | 展示 `getInstallSourceInfo` / `getInstallerPackageName` 与 installer/sideload indicators 组合形成的安装来源 environment evidence |
| `java_debug_api_probe` | 展示 Java 层 `android.os.Debug` / `waitingForDebugger` 反调试 evidence |
| `signature_integrity_check` | 展示 PackageManager signature API 与 digest 组合形成的反篡改/自完整性 evidence |
| `root_artifact_probe` | 展示 `su` 路径、Superuser/Magisk 包名和 `test-keys` root 环境 evidence |
| `native_ptrace_loader` | 展示 ELF 符号级 Native anti-debug / loader evidence |
| `emulator_imei_probe` | 展示 emulator telephony/device-id probe |
| `pivaa` | 外部现成 APK，用于证明真实 APK 也能扫描 |
| `fdroid_editor` | F-Droid 真实 APK baseline，用于展示正常样本低误报 |

页面还支持上传本地 `.apk` 文件。上传扫描只在本地服务进程中写入临时目录，扫描完成后临时文件自动删除；默认大小上限为 64 MiB。

扫描后页面展示四类 summary 计数、样本故事、finding 列表和 evidence 表。Benchmark 区域直接读取 `reports/benchmark/benchmark_metrics.csv`，展示 HardenInspector 与 APKiD、Androguard DEX、ZIP Strings 的 micro/macro Precision、Recall、F1。

## API

页面使用四个本地接口：

| 接口 | 返回 |
| --- | --- |
| `/api/samples` | 可展示样本列表、路径、来源、说明和期望类别 |
| `/api/scan?id=<sample_id>` | 指定样本的 HardenInspector JSON report |
| `/api/scan-upload?filename=<name.apk>` | 上传 APK bytes 后返回 HardenInspector JSON report |
| `/api/metrics` | `reports/benchmark/benchmark_metrics.csv` 解析后的指标行 |
| `/assets/apk-cutaway.png` | 展示页使用的 APK 静态分析拆解图；支持 `GET` 和 `HEAD` |

这些接口只读取仓库内已提交的 APK/报告文件或浏览器上传的本地 APK bytes，不向外部上传数据，也不需要联网。
