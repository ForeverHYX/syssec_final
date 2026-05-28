# 开源实现对比与可靠性验证

本项目使用外部工具作为验证基准，而不是改变 HardenInspector 的技术路线。检测器仍遵照中期报告：静态解析 APK/Manifest/DEX/Native，提取可解释特征，通过规则引擎输出证据链。

## 公平性原则

默认 benchmark 只纳入同时满足以下条件的比较对象：

- 能通过 `make setup` 安装；
- 能通过 `make benchmark` 在本仓库合并评分数据集上完成 34/34 个样本；
- 能产生可映射到 `packer`、`obfuscation`、`environment`、`native` 的类别输出；
- 失败时不把“缺环境/缺外部工具”记为 0 分。

DroidLysis 和 MobSF 不再进入默认评分表。DroidLysis 依赖 apktool/baksmali/dex2jar 等外部管线；MobSF 需要更重的服务或 Docker 工作流。它们保留为定性参照，避免不可用环境造成不公平统计。

## 默认评分对象

### HardenInspector

本项目检测器，作为目标实现。它使用仓库内解析器读取 APK ZIP、Manifest string pool、DEX、Native `.so` 和资源文件，并输出 evidence chain。

### APKiD

APKiD 是 Android packer、protector、obfuscator 和 oddity identifier，并支持 JSON 输出。

项目链接：https://github.com/rednaga/APKiD

本项目使用 APKiD 3.1.0，映射关系如下：

| APKiD 类别 | 本项目类别 |
| --- | --- |
| `packer` | `packer` |
| `obfuscator`、`anti_disassembly` | `obfuscation` |
| `anti_vm`、`anti_debug` | `environment` |

### Androguard DEX

Androguard 是 Android 应用逆向和分析工具，支持 DEX/APK 等 Android 文件。

项目链接：https://github.com/androguard/androguard

本项目使用 Androguard 4.1.3 作为 DEX 结构解析基线：读取 DEX strings/classes/methods，再做浅层类别映射。它不读取 Manifest、Native 库或资源文件，因此 Native 类别 recall 预期较低。

### ZIP Strings

ZIP Strings 是仓库内的最小浅层基线：只读取 APK ZIP 文件名和 printable strings，不理解 Android 结构。它用于说明“简单字符串扫描”与 HardenInspector 的结构化证据链之间的差异。

## 定性参照

- DroidLysis：https://pypi.org/project/droidlysis/
- MobSF：https://github.com/MobSF/Mobile-Security-Framework-MobSF

这两个工具没有进入默认评分表；报告中不再把它们的不可用环境结果作为 0 分。

## 数据集

Benchmark 使用两个数据源合并评分：

- 22 个合成 APK；
- 覆盖 clean baseline、环境检测、Java Debug API 反调试、ADB/developer-settings 系统设置探测、installer-source/sideload 安装来源探测、R8 风格标识符混淆、Obfuscapk 风格反射/动态加载、两类 packer stub/payload、Native JNI bridge、Frida/Xposed 探测、reflection-only dispatch、控制流密度样本、高熵 payload-only 样本、Native ptrace/loader ELF 符号样本、Class.forName 反射、模拟器文件痕迹、IMEI 设备标识探测、JNI `Java_*` 导出符号、signature integrity/self-check、root/rooted-device artifact probe、综合加固样本；
- 每个样本包含 expected findings 和当前检测器报告；
- 合成 DEX 包含标准 checksum、signature 和 map list，保证 Androguard DEX baseline 可解析。
- 12 个外部现成 APK，来自 DroidBench、F-Droid、PIVAA；`manifest.json` 为每个外部样本记录粗粒度 `expected_categories` 和 `label_basis`，纳入同一 Precision/Recall/F1 评分表。

## 运行命令

```bash
make benchmark
```

等价于：

```bash
.venv/bin/python -m hardeninspector.benchmark \
  --dataset datasets/hardeninspector_eval_v1 \
  --score-external-corpus datasets/external_apk_corpus_v1 \
  --output reports/benchmark \
  --tools hardeninspector apkid androguard_dex zip_string_baseline
```

输出：

- `reports/benchmark/benchmark_results.json`
- `reports/benchmark/benchmark_metrics.csv`
- `reports/benchmark/benchmark_summary.md`

外部现成 APK 统计：

```bash
make external-corpus
```

输出：

- `reports/external_corpus/external_corpus_results.json`
- `reports/external_corpus/external_corpus_counts.csv`
- `reports/external_corpus/external_corpus_summary.md`

## 统计结果

当前 benchmark 结果：

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 34/34 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 34/34 | 1.000 | 0.186 | 0.314 | 0.234 |
| Androguard DEX | 34/34 | 0.800 | 0.488 | 0.609 | 0.516 |
| ZIP Strings | 34/34 | 0.829 | 0.698 | 0.759 | 0.740 |

测试状态：`.venv/bin/python -m pytest -q` 为 69 个测试通过；`make benchmark` 在当前仓库环境中重新生成上述统计。

分类细节：

- `packer`：HardenInspector TP 10 / FN 0，APKiD TP 3，Androguard DEX TP 7，ZIP Strings TP 9。
- `obfuscation`：HardenInspector TP 8 / FN 0，APKiD TP 0，Androguard DEX TP 4，ZIP Strings TP 4。
- `environment`：HardenInspector TP 16 / FN 0，APKiD TP 5，Androguard DEX TP 10，ZIP Strings TP 12。
- `native`：HardenInspector TP 9 / FN 0，APKiD TP 0，Androguard DEX TP 0，ZIP Strings TP 5。

## 结果解释

APKiD 对 packer 指纹和部分 anti-vm 信号表现稳定，但它的目标是识别 packer/protector/obfuscator/oddity 指纹，不覆盖本项目的 Native 入口证据和大部分课程构造的 reflection/short-identifier 标签。

Androguard DEX baseline 证明合成 DEX 可以被真实开源 parser 解析。它能命中 DEX 内的动态加载、反射、短类名和环境字符串，但因为只看 DEX strings/classes/methods，不看 Manifest/Native/resource，也不复刻 HardenInspector 的 opcode-density 与 ELF-symbol 规则，所以 Native 类别为 0/9，控制流和 Native 符号样本不命中。

ZIP Strings baseline 说明浅层字符串扫描在本数据集上也能捕获很多显式字符串和符号名，但它没有结构化 evidence chain，无法区分 Manifest、DEX、Native、资源上下文，也不能从 bytecode opcode 分布中识别控制流密度或从文件统计中解释高熵 payload。

HardenInspector 的优势来自中期报告路线中的多源结构化证据：Manifest + DEX + Native + 资源文件 + 规则证据链，而不是复制 APKiD/Androguard 的实现。

## 外部 APK 统计

为扩大测试范围，仓库额外纳入 12 个公开现成 APK：DroidBench 10 个、F-Droid 1 个、PIVAA 1 个。它们现在进入 `make benchmark` 的 33 样本合并评分；`make external-corpus` 仍保留单独的扫描覆盖和 finding 分布表。

| Tool | Samples | Any category | Packer | Obfuscation | Environment | Native |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 12/12 | 10 | 4 | 2 | 5 | 3 |
| APKiD | 12/12 | 2 | 0 | 0 | 2 | 0 |
| Androguard DEX | 12/12 | 8 | 3 | 6 | 2 | 0 |
| ZIP Strings | 12/12 | 10 | 4 | 6 | 4 | 0 |

测试状态：`make external-corpus` 和 fresh venv 外部语料复核均能完成四个工具的 12/12 coverage。

外部样本暴露出两个误报调优点：早期 `control_flow_density` 对 F-Droid 普通 APK 命中过敏；早期 reflection 规则也会把 Android support library 的兼容层反射样板报成应用混淆。当前规则已分别收紧为“控制流 opcode 数和密度同时超过阈值”和“反射证据需要强字面量或应用自有上下文”，`fdroid_editor` 已无 finding；`droidbench_reflection_5` 的可见反射证据也被审计为 support-library-only，因此不再作为应用混淆 oracle。root/test-key artifact 则作为环境探测补充信号保留，在 DroidBench emulator build 样本和合成 root 样本中可复查。

## 局限

- 数据集是合成可复现数据集，不等价于大规模真实 APK 生态。
- 外部 APK 的标签是粗粒度评估映射，不等同于官方 hardening ground truth；报告中通过 `label_basis` 记录每个映射依据。
- ZIP Strings 对合成样本较强，是因为样本显式植入了可观测字符串；真实加密/压缩样本下会明显退化。
- APKiD 的 `compiler` 类输出没有纳入本项目类别，因为 HardenInspector 的目标不是编译器识别。
- DroidLysis/MobSF 的完整能力需要更重的外部环境，因此只保留定性说明，不进入默认评分。
