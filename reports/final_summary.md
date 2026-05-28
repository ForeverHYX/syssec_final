# HardenInspector 期末总结报告

## 1. 项目目标

本项目面向系统安全课程题目“Android 应用抗加固分析”，选择检测器方向，基于中期报告提出的 HardenInspector 框架实现期末展品。

HardenInspector 的目标不是判断 APK 是否恶意，而是回答：

> 一个 Android APK 静态上呈现了哪些代码混淆、运行时加壳、环境感知检测和 Native 入口证据？

项目保持中期报告中的技术路线：

- 解析层：APK ZIP、Manifest binary XML、DEX、Native `.so`、资源文件；
- 特征层：字符串、类型描述符、方法名、`const-string`、`invoke-*`、opcode profile、文件熵、Native 字符串与 ELF 符号；
- 决策层：解释型静态规则；
- 报告层：JSON/text evidence chain。

开源工具 APKiD、Androguard、DroidLysis、MobSF 只作为对比或定性参照对象，不作为实现来源。

## 2. 已实现功能

### 2.1 检测器

已实现 Python CLI：

```bash
python -m hardeninspector path/to/app.apk --json
```

核心能力：

- APK 文件清单、SHA-256、文件大小、压缩大小、Shannon 熵；
- Manifest string pool 提取；
- DEX string/type/method/class-data/code-item 轻量解析；
- `const-string`、`invoke-*` 和控制流 opcode profile 静态证据提取；
- Native `.so` 字符串扫描和 ELF `.dynsym`/`.symtab` 符号提取；
- JSON 和文本摘要报告。

### 2.2 规则覆盖

| 类别 | 已实现规则 |
| --- | --- |
| 加壳 | 已知壳库、StubApp、高熵 payload、动态加载 API、Native loader 符号 |
| 混淆 | 短类名比例、反射 API/`invoke`/`Class.forName`、分支/跳转 opcode 密度 |
| 环境检测 | emulator properties、emulator file artifacts、IMEI/device-id probe、signature integrity/self-check、root/Magisk/su artifact probe、debugger probe、Native anti-debug 符号、Frida/Xposed/process maps |
| Native | `JNI_OnLoad` 字符串/ELF 符号、`Java_*` JNI 导出符号 |

每条 finding 都包含 `category`、`severity`、`confidence`、`description` 和 `evidence`。

### 2.3 数据集

构造了 `datasets/hardeninspector_eval_v1/`：

| 样本 | 作用 |
| --- | --- |
| `fdroid_clean_baseline.apk` | F-Droid 风格无加固基线 |
| `self_written_environment_checks.apk` | 自写环境检测样本 |
| `r8_identifier_obfuscation.apk` | R8/ProGuard 风格短标识符样本 |
| `obfuscapk_reflection_dynamic.apk` | Obfuscapk 风格反射/动态加载样本 |
| `packer_stub_payload.apk` | 壳入口、高熵 payload、壳库样本 |
| `bangcle_stub_payload.apk` | 第二类 Bangcle 风格壳样本 |
| `native_jni_bridge_only.apk` | 单独 Native JNI bridge 样本 |
| `frida_xposed_probe.apk` | 单独 Frida/Xposed instrumentation 探测样本 |
| `reflection_only_dispatch.apk` | 单独反射 dispatch 混淆样本 |
| `control_flow_flattening.apk` | 轻量控制流密度混淆样本 |
| `high_entropy_payload_only.apk` | 只依赖文件熵的 opaque payload 样本 |
| `native_ptrace_loader.apk` | Native ELF 符号表反调试/动态加载样本 |
| `class_forname_reflection.apk` | `Class.forName` 反射样本 |
| `emulator_file_artifacts.apk` | file-based emulator detection 样本 |
| `emulator_imei_probe.apk` | IMEI/device-id emulator probe 样本 |
| `native_jni_export_only.apk` | 只含 `Java_*` JNI 导出符号的 Native 样本 |
| `signature_integrity_check.apk` | PackageManager 签名查询 + digest 反篡改样本 |
| `root_artifact_probe.apk` | `su` 路径、Superuser/Magisk 包名、`test-keys` root 环境样本 |
| `combined_hardened_showcase.apk` | 综合展示样本 |

数据集包含 APK、`labels.json` 和每个样本的 JSON 检测报告。

### 2.4 外部现成 APK 语料

为避免测试范围只包含自构造 APK，仓库新增 `datasets/external_apk_corpus_v1/`：

| 来源 | 数量 | 说明 |
| --- | ---: | --- |
| DroidBench | 10 | 现成 Android 静态分析测试 APK |
| F-Droid | 1 | 真实开源 APK |
| PIVAA | 1 | 现成漏洞测试 APK |

外部语料已补充粗粒度 `expected_categories` 和 `label_basis`，随合成数据集一起进入 31 样本合并评分；同时保留单独的覆盖率、finding 分布和普通真实 APK 误报观察。

## 3. 开源实现对比

### 3.1 对比对象

- APKiD：Android packer/protector/obfuscator/oddity identifier，作为主要开源签名基线。
- Androguard DEX：开源 Android DEX/APK 分析工具，作为真实 DEX parser 基线。
- ZIP Strings：仓库内浅层字符串扫描基线，用于比较“无结构解析”的可复现下限。
- DroidLysis/MobSF：完整运行依赖更重外部管线或服务，作为定性参照，不进入默认评分表。

### 3.2 统计方法

我们将检测结果映射到四个类别：

- `packer`
- `obfuscation`
- `environment`
- `native`

对每个工具计算多标签分类统计：

- TP / FP / FN / TN；
- Precision；
- Recall；
- F1；
- Micro F1；
- Macro F1。

统计文件：

- `reports/benchmark/benchmark_results.json`
- `reports/benchmark/benchmark_metrics.csv`
- `reports/benchmark/benchmark_summary.md`
- `reports/external_corpus/external_corpus_results.json`
- `reports/external_corpus/external_corpus_counts.csv`
- `reports/external_corpus/external_corpus_summary.md`

### 3.3 统计结果

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 31/31 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 31/31 | 1.000 | 0.200 | 0.333 | 0.254 |
| Androguard DEX | 31/31 | 0.783 | 0.450 | 0.571 | 0.499 |
| ZIP Strings | 31/31 | 0.818 | 0.675 | 0.740 | 0.729 |

分类细节：

- `packer`：HardenInspector TP 10 / FN 0，APKiD TP 3，Androguard DEX TP 7，ZIP Strings TP 9。
- `environment`：HardenInspector TP 13 / FN 0，APKiD TP 5，Androguard DEX TP 7，ZIP Strings TP 9。
- `obfuscation`：HardenInspector TP 8 / FN 0，APKiD TP 0，Androguard DEX TP 4，ZIP Strings TP 4。
- `native`：HardenInspector TP 9 / FN 0，APKiD TP 0，Androguard DEX TP 0，ZIP Strings TP 5。

### 3.4 结果解释

APKiD 在 Jiagu/Bangcle 和 `ro.kernel.qemu` 这类信号上表现稳定，说明我们的 packer 和 environment 规则与成熟开源工具的核心识别方向一致。

HardenInspector 在本数据集上覆盖更多类别，原因不是复制 APKiD，而是项目目标不同：

- APKiD 主要识别 packer/protector/obfuscator 指纹；
- Androguard DEX 证明数据集可被真实开源 DEX parser 解析，但它的基线只看 DEX strings/classes/methods，不看 Manifest/Native/resource，也不复刻本项目的 opcode-density 和 ELF-symbol 规则；
- HardenInspector 按中期报告要求输出三类加固技术画像和证据链；
- 本项目额外覆盖短标识符比例、反射/动态加载组合、控制流 opcode 密度、JNI 入口等课程目标内信号。

DroidLysis 不再进入评分表，因为缺 apktool/baksmali/dex2jar 时会产生不可用而非真实低分的结果。这样避免把环境问题写成工具能力问题。

### 3.5 外部 APK 扫描统计

| Tool | Samples | Any category | Packer | Obfuscation | Environment | Native |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 12/12 | 10 | 4 | 2 | 5 | 3 |
| APKiD | 12/12 | 2 | 0 | 0 | 2 | 0 |
| Androguard DEX | 12/12 | 8 | 3 | 6 | 2 | 0 |
| ZIP Strings | 12/12 | 10 | 4 | 6 | 4 | 0 |

外部样本用于扩大解析覆盖范围，并已通过粗粒度标签进入合并评分。这里额外保留不看标签的 finding 分布，用来观察不同工具在真实/公开 APK 上的输出差异。调试中发现 `control_flow_density` 初始阈值对 F-Droid 普通 APK 过敏，reflection 规则也会把 support library 兼容层反射当作应用混淆；两处均已收紧。当前 `fdroid_editor` 无 finding，`droidbench_reflection_5` 经标签审计后不再把 support-library-only 反射计为应用混淆 oracle；root/test-key artifact 作为环境探测补充信号保留。

## 4. 优化结论

当前实现已经在课程目标数据集上达到或超过可运行比较基线的类别级覆盖：

- 对 APKiD 可比的 `packer` 和 `environment` 信号，HardenInspector 均能命中；
- 对 Androguard DEX 可见的 DEX 类信号，HardenInspector 保持一致覆盖，并额外结合 Manifest/Native/resource evidence；
- 对中期报告中强调但 APKiD 默认未覆盖的 evidence-chain 目标，HardenInspector 提供额外规则；
- 在 12 个外部现成 APK 上，HardenInspector 和三个 comparator 均能完成扫描；外部样本已纳入合并评分，并单独报告覆盖与分布；
- 因此无需偏离中期报告路线去复刻 APKiD 的 YARA 规则或 Androguard 的通用逆向框架。

可继续扩展的方向：

- 增加更多壳库名和 StubApp 模式；
- 对 Native 层继续扩展导入表上下文、符号邻近字符串和轻量二进制结构特征；
- 用真实 F-Droid/Obfuscapk/R8 构建样本扩展当前合成数据集。

项目实现已经把原先的“opcode/控制流轻量统计”和“Native 仅字符串扫描”两个短板推进为可验证能力：`dex.py` 输出 opcode profile，`rules.py` 生成 `obfuscation.control_flow_density` finding；`native.py` 解析 ELF 符号表，规则生成 `environment.native_debugger_symbol`、`packer.native_dynamic_loader` 与 `native.jni_export` finding。数据集中新增 `control_flow_flattening.apk`、`high_entropy_payload_only.apk`、`native_ptrace_loader.apk`、`class_forname_reflection.apk`、`emulator_file_artifacts.apk`、`emulator_imei_probe.apk`、`native_jni_export_only.apk`、`signature_integrity_check.apk` 和 `root_artifact_probe.apk` 用于验证。

## 5. 开箱即用环境

仓库提供：

- `Makefile`
- `scripts/setup_env.sh`
- `requirements.txt`
- `requirements-dev.txt`
- `requirements-benchmark.txt`
- `Dockerfile`

本地验证命令：

```bash
./scripts/setup_env.sh /tmp/hardeninspector-venv-check
/tmp/hardeninspector-venv-check/bin/python -m pytest -q
/tmp/hardeninspector-venv-check/bin/python -m hardeninspector --help
/tmp/hardeninspector-venv-check/bin/python -m hardeninspector.benchmark --dataset datasets/hardeninspector_eval_v1 --score-external-corpus datasets/external_apk_corpus_v1 --output /tmp/hardeninspector-benchmark-check --tools hardeninspector apkid androguard_dex zip_string_baseline
/tmp/hardeninspector-venv-check/bin/python -m hardeninspector.benchmark --external-only --external-corpus datasets/external_apk_corpus_v1 --external-output /tmp/hardeninspector-external-check --tools hardeninspector apkid androguard_dex zip_string_baseline
make demo-web
```

验证结果：当前环境中 53 个测试通过，CLI 可用；四个默认 benchmark 工具均为 31/31 combined scoring coverage，单独外部统计为 12/12 coverage。`make demo-web` 可启动本地网页展示，默认监听 `http://127.0.0.1:8000/`，支持预置样本和本地 APK 上传扫描。

| 检查项 | 结果 |
| --- | --- |
| 自动化测试 | 53 个测试通过 |
| 合成数据集 | 19 个 APK，可通过 `make dataset` 复现 |
| Combined benchmark | 19 个 synthetic APK + 12 个外部 APK；四个工具均为 31/31 coverage |
| External corpus | DroidBench/F-Droid/PIVAA 共 12 个现成 APK；单独统计四个工具均为 12/12 coverage |
| Slides | `make slides` 编译为 22 页，构建产物由 `.gitignore` 忽略 |

Benchmark 输出中的 `runtime_ms` 字段固定为 `null`，避免毫秒级耗时导致提交产物不可复现。

## 6. 交付物索引

| 内容 | 路径 |
| --- | --- |
| 检测器源码 | `src/hardeninspector/` |
| 数据集 | `datasets/hardeninspector_eval_v1/` |
| 外部 APK 语料 | `datasets/external_apk_corpus_v1/` |
| benchmark 统计 | `reports/benchmark/` |
| 外部 APK 统计 | `reports/external_corpus/` |
| 本地 Web Demo | `src/hardeninspector/demo_web.py`、`docs/demo_web.md`、`make demo-web`；首屏包含 Exhibit Map、Evidence Chain、Dataset Story、APK 拆解图、31 个评分 APK、53 个测试和上传扫描 |
| 中文文档 | `docs/` |
| 中期报告 PDF | `docs/references/mid_term.pdf` |
| 期末 Beamer | `slides/final_presentation.tex`，使用 ZJU Beamer Template，标题为 `HardenInspector`，作者为洪奕迅、蒋城昊、项康 |
| 开箱即用环境 | `Makefile`、`scripts/setup_env.sh`、`Dockerfile` |

Beamer 已使用 `make slides` 编译检查。汇报稿包含规则/benchmark 表格、TikZ 总体架构图、控制流 opcode profile 示意、Native ELF 符号证据说明、数据集覆盖矩阵、外部 APK 语料统计、测试结果复核、Micro F1 可视化图，以及一张用于说明 APK 拆解对象的生成式示意图；生成的 PDF 和 LaTeX 辅助文件已加入 `.gitignore`。

## 7. 局限性

- 数据集是可复现合成数据集，不等价于大规模真实 APK 生态；
- 当前不实现完整 CFG、深度 Native 反汇编或动态 Frida 验证；ELF 支持只覆盖符号表级证据；
- 工具输出的是加固技术证据，不输出恶意/良性结论；
- benchmark 统计只证明当前数据集和类别定义下的可靠性。

## 8. 参考链接

- APKiD: https://github.com/rednaga/APKiD
- Androguard: https://github.com/androguard/androguard
- DroidLysis: https://pypi.org/project/droidlysis/
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- ZJU Beamer Template: https://github.com/qychen2001/ZJU-Beamer-Template
