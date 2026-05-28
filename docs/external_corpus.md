# 外部 APK 语料说明

本项目除了可复现合成数据集，还纳入了公开现成 APK，作为真实/外部样本扫描统计。

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

## 为什么不计算 F1

这些外部 APK 没有 HardenInspector 四类 hardening 标签的 ground truth。DroidBench 主要服务于 taint-analysis benchmark；PIVAA 主要服务于移动漏洞扫描器测试；F-Droid 样本是普通开源应用。因此外部语料只用于：

- APK 解析覆盖率；
- 每个工具是否能跑完；
- finding/category 分布；
- 普通真实 APK 的误报观察。

Precision、Recall、Micro F1、Macro F1 仍只在 `datasets/hardeninspector_eval_v1/` 合成 oracle 数据集上计算。

## 运行

```bash
make external-corpus
```

输出：

- `reports/external_corpus/external_corpus_results.json`
- `reports/external_corpus/external_corpus_counts.csv`
- `reports/external_corpus/external_corpus_summary.md`

## 当前统计

| Tool | Samples | Any category | Packer | Obfuscation | Environment | Native |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 12/12 | 9 | 3 | 6 | 3 | 0 |
| APKiD | 12/12 | 2 | 0 | 0 | 2 | 0 |
| Androguard DEX | 12/12 | 8 | 3 | 6 | 1 | 0 |
| ZIP Strings | 12/12 | 9 | 3 | 6 | 2 | 0 |

重要观察：

- `fdroid_editor` 是真实开源 APK，当前 HardenInspector 无 finding，说明收紧后的控制流密度规则没有在该普通样本上误报。
- DroidBench 的 reflection/dynamic-loading/emulator 场景能触发对应静态证据，说明检测器不仅能扫描合成 APK，也能处理公开现成测试 APK。
- PIVAA 同时触发 dynamic loading、reflection 和 instrumentation 字符串，适合作为安全测试 APK 的外部 smoke sample。

## 不能作为有标签 benchmark 的原因

外部 APK 的标签目标和 HardenInspector 不同。把 DroidBench 或 PIVAA 的漏洞/污点标签直接映射成 hardening 标签会造成不公平统计。因此报告中明确区分：

- `hardeninspector_eval_v1`：可计算 F1 的合成 oracle 数据集；
- `external_apk_corpus_v1`：现成 APK 的扫描覆盖和分布统计。
