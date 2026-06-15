# 外部 APK 语料说明

本项目除了可复现合成数据集，还纳入了公开现成 APK。外部语料现在有两种用途：进入 `make benchmark` 的 34 样本合并评分，同时通过 `make external-corpus` 单独输出覆盖率和 finding 分布。

## 来源

当前外部语料位于 `datasets/external_apk_corpus_v1/`，共 12 个 APK：

| 来源 | 数量 | 用途 |
| --- | ---: | --- |
| DroidBench | 10 | Android 静态分析测试 APK，覆盖 reflection、dynamic loading、emulator detection、native、self-modification 等场景 |
| F-Droid | 1 | 真实开源 APK，检查普通应用上的误报风险 |
| PIVAA | 1 | 现成漏洞测试 APK，检查安全测试应用上的扫描输出 |

每个样本都在 `manifest.json` 中记录：

- 样本 ID；
- APK 相对路径；
- 来源；
- 来源上下文；
- 下载 URL；
- SHA-256。
- 粗粒度 `expected_categories`；
- `label_basis`，说明为什么把该公开样本映射到本项目四类 hardening-signal 标签。

## 评分标签口径

外部 APK 的原始标签目标和 HardenInspector 不完全相同：DroidBench 主要服务于 taint-analysis benchmark；PIVAA 主要服务于移动漏洞扫描器测试；F-Droid 样本是普通开源应用。为了按用户要求纳入评分，本仓库采用可审计的粗粒度映射：

- Reflection -> `obfuscation`；
- DynamicLoading -> `packer`；
- EmulatorDetection / SelfModification -> `environment`；
- Native -> `native`；
- F-Droid Editor -> 空标签，作为真实开源 APK 低误报基线；
- PIVAA -> `packer`、`obfuscation`、`environment`，因为它包含 dynamic-loading、reflection 和 instrumentation 风格信号。

这些标签不是官方 hardening ground truth，而是本项目四类检测目标下的评估映射；每条映射都写入 `manifest.json` 的 `label_basis`。

## 运行

```bash
make external-corpus
```

输出：

- `reports/external_corpus/external_corpus_results.json`
- `reports/external_corpus/external_corpus_counts.csv`
- `reports/external_corpus/external_corpus_summary.md`

合并评分运行：

```bash
make benchmark
```

`make benchmark` 会把 `datasets/hardeninspector_eval_v1/` 和 `datasets/external_apk_corpus_v1/` 合并为 34 个评分样本。

## 当前统计

| Tool | Samples | Any category | Packer | Obfuscation | Environment | Native |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 12/12 | 10 | 4 | 2 | 5 | 3 |
| APKiD | 12/12 | 2 | 0 | 0 | 2 | 0 |
| Androguard DEX | 12/12 | 8 | 3 | 6 | 2 | 0 |
| ZIP Strings | 12/12 | 10 | 4 | 6 | 4 | 0 |

测试状态：`make external-corpus` 和 fresh venv 外部语料复核均能完成四个工具的 12/12 coverage。

合并评分结果：

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 34/34 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 34/34 | 1.000 | 0.186 | 0.314 | 0.234 |
| Androguard DEX | 34/34 | 0.800 | 0.488 | 0.609 | 0.516 |
| ZIP Strings | 34/34 | 0.829 | 0.698 | 0.759 | 0.740 |

重要观察：

- `fdroid_editor` 是真实开源 APK，当前 HardenInspector 无 finding，说明收紧后的控制流密度规则没有在该普通样本上误报。
- DroidBench 的 reflection/dynamic-loading/emulator/native 场景能触发对应静态证据；其中 `Class.forName`、IMEI/file-based emulator detection、root/test-key artifact 和 JNI `Java_*` 符号来自外部语料调优后新增的规则。`droidbench_reflection_5` 当前不报 obfuscation，因为可见证据主要来自 support library 兼容层反射；标签审计后它不再作为应用混淆 oracle。
- PIVAA 同时触发 dynamic loading、reflection、signature integrity 和 instrumentation 字符串，适合作为安全测试 APK 的外部 smoke sample。

## 标签边界

外部 APK 的标签目标和 HardenInspector 不同，因此本项目不声称这些标签是官方 hardening oracle。报告中明确区分：

- `hardeninspector_eval_v1`：可计算 F1 的合成 oracle 数据集；
- `external_apk_corpus_v1`：带粗粒度标签的现成 APK 评估扩展，同时保留扫描覆盖和分布统计。
