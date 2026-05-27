# HardenInspector 期末总结报告

## 1. 项目目标

本项目面向系统安全课程题目“Android 应用抗加固分析”，选择检测器方向，基于中期报告提出的 HardenInspector 框架实现期末展品。

HardenInspector 的目标不是判断 APK 是否恶意，而是回答：

> 一个 Android APK 静态上呈现了哪些代码混淆、运行时加壳、环境感知检测和 Native 入口证据？

项目保持中期报告中的技术路线：

- 解析层：APK ZIP、Manifest binary XML、DEX、Native `.so`、资源文件；
- 特征层：字符串、类型描述符、方法名、`const-string`、`invoke-*`、opcode profile、文件熵、Native 字符串；
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
- Native `.so` 字符串扫描；
- JSON 和文本摘要报告。

### 2.2 规则覆盖

| 类别 | 已实现规则 |
| --- | --- |
| 加壳 | 已知壳库、StubApp、高熵 payload、动态加载 API |
| 混淆 | 短类名比例、反射 API/`invoke`、分支/跳转 opcode 密度 |
| 环境检测 | emulator properties、debugger probe、Frida/Xposed/process maps |
| Native | `JNI_OnLoad` |

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
| `combined_hardened_showcase.apk` | 综合展示样本 |

数据集包含 APK、`labels.json` 和每个样本的 JSON 检测报告。

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

### 3.3 统计结果

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 11/11 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 11/11 | 1.000 | 0.312 | 0.476 | 0.414 |
| Androguard DEX | 11/11 | 1.000 | 0.625 | 0.769 | 0.688 |
| ZIP Strings | 11/11 | 1.000 | 0.875 | 0.933 | 0.938 |

分类细节：

- `packer`：HardenInspector 4/4，APKiD 3/4，Androguard DEX 4/4，ZIP Strings 4/4。
- `environment`：HardenInspector 3/3，APKiD 2/3，Androguard DEX 3/3，ZIP Strings 3/3。
- `obfuscation`：HardenInspector 5/5，APKiD 0/5，Androguard DEX 3/5，ZIP Strings 3/5。
- `native`：HardenInspector 4/4，APKiD 0/4，Androguard DEX 0/4，ZIP Strings 4/4。

### 3.4 结果解释

APKiD 在 Jiagu/Bangcle 和 `ro.kernel.qemu` 这类信号上表现稳定，说明我们的 packer 和 environment 规则与成熟开源工具的核心识别方向一致。

HardenInspector 在本数据集上覆盖更多类别，原因不是复制 APKiD，而是项目目标不同：

- APKiD 主要识别 packer/protector/obfuscator 指纹；
- Androguard DEX 证明数据集可被真实开源 DEX parser 解析，但它的基线只看 DEX strings/classes/methods，不看 Manifest/Native/resource，也不复刻本项目的 opcode-density 规则；
- HardenInspector 按中期报告要求输出三类加固技术画像和证据链；
- 本项目额外覆盖短标识符比例、反射/动态加载组合、控制流 opcode 密度、JNI 入口等课程目标内信号。

DroidLysis 不再进入评分表，因为缺 apktool/baksmali/dex2jar 时会产生不可用而非真实低分的结果。这样避免把环境问题写成工具能力问题。

## 4. 优化结论

当前实现已经在课程目标数据集上达到或超过可运行比较基线的类别级覆盖：

- 对 APKiD 可比的 `packer` 和 `environment` 信号，HardenInspector 均能命中；
- 对 Androguard DEX 可见的 DEX 类信号，HardenInspector 保持一致覆盖，并额外结合 Manifest/Native/resource evidence；
- 对中期报告中强调但 APKiD 默认未覆盖的 evidence-chain 目标，HardenInspector 提供额外规则；
- 因此无需偏离中期报告路线去复刻 APKiD 的 YARA 规则或 Androguard 的通用逆向框架。

后续优化方向：

- 增加更多壳库名和 StubApp 模式；
- 对 Native 层引入符号表、导入表和轻量字符串上下文；
- 用真实 F-Droid/Obfuscapk/R8 构建样本扩展当前合成数据集。

本轮已把原先的“opcode/控制流轻量统计”从后续方向推进为已实现能力：`dex.py` 输出 opcode profile，`rules.py` 生成 `obfuscation.control_flow_density` finding，数据集中新增 `control_flow_flattening.apk` 用于验证。

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
/tmp/hardeninspector-venv-check/bin/python -m hardeninspector.benchmark --dataset datasets/hardeninspector_eval_v1 --output /tmp/hardeninspector-benchmark-check --tools hardeninspector apkid androguard_dex zip_string_baseline
```

验证结果：fresh venv 中 25 个测试通过，CLI 可用；四个默认 benchmark 工具均为 11/11 coverage。

Benchmark 输出中的 `runtime_ms` 字段固定为 `null`，避免毫秒级耗时导致提交产物不可复现。

## 6. 交付物索引

| 内容 | 路径 |
| --- | --- |
| 检测器源码 | `src/hardeninspector/` |
| 数据集 | `datasets/hardeninspector_eval_v1/` |
| benchmark 统计 | `reports/benchmark/` |
| 中文文档 | `docs/` |
| 中期报告 PDF | `docs/references/mid_term.pdf` |
| 期末 Beamer | `slides/final_presentation.tex`，使用 ZJU Beamer Template，标题为 `HardenInspector`，作者为洪奕迅、蒋城昊、项康 |
| 开箱即用环境 | `Makefile`、`scripts/setup_env.sh`、`Dockerfile` |

Beamer 已使用 `make slides` 编译检查。汇报稿包含规则/benchmark 表格、TikZ 总体架构图、控制流 opcode profile 示意、数据集覆盖矩阵、Micro F1 可视化图，以及一张用于说明 APK 拆解对象的生成式示意图；生成的 PDF 和 LaTeX 辅助文件已加入 `.gitignore`。

## 7. 局限性

- 数据集是可复现合成数据集，不等价于大规模真实 APK 生态；
- 当前不实现完整 CFG、深度 Native 反汇编或动态 Frida 验证；
- 工具输出的是加固技术证据，不输出恶意/良性结论；
- benchmark 统计只证明当前数据集和类别定义下的可靠性。

## 8. 参考链接

- APKiD: https://github.com/rednaga/APKiD
- Androguard: https://github.com/androguard/androguard
- DroidLysis: https://pypi.org/project/droidlysis/
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- ZJU Beamer Template: https://github.com/qychen2001/ZJU-Beamer-Template
