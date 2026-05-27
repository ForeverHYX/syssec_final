# HardenInspector 期末总结报告

## 1. 项目目标

本项目面向系统安全课程题目“Android 应用抗加固分析”，选择检测器方向，基于中期报告提出的 HardenInspector 框架实现期末展品。

HardenInspector 的目标不是判断 APK 是否恶意，而是回答：

> 一个 Android APK 静态上呈现了哪些代码混淆、运行时加壳、环境感知检测和 Native 入口证据？

项目保持中期报告中的技术路线：

- 解析层：APK ZIP、Manifest binary XML、DEX、Native `.so`、资源文件；
- 特征层：字符串、类型描述符、方法名、`const-string`、`invoke-*`、文件熵、Native 字符串；
- 决策层：解释型静态规则；
- 报告层：JSON/text evidence chain。

开源工具 APKiD、DroidLysis、MobSF 只作为对比对象，不作为实现来源。

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
- `const-string` 和 `invoke-*` 静态证据提取；
- Native `.so` 字符串扫描；
- JSON 和文本摘要报告。

### 2.2 规则覆盖

| 类别 | 已实现规则 |
| --- | --- |
| 加壳 | 已知壳库、StubApp、高熵 payload、动态加载 API |
| 混淆 | 短类名比例、反射 API/`invoke` |
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
| `combined_hardened_showcase.apk` | 综合展示样本 |

数据集包含 APK、`labels.json` 和每个样本的 JSON 检测报告。

## 3. 开源实现对比

### 3.1 对比对象

- APKiD：Android packer/protector/obfuscator/oddity identifier，作为主要可运行基线。
- DroidLysis：Android suspicious sample pre-analysis 工具，本地运行需要 apktool/baksmali/dex2jar 等外部工具，因此作为有限环境对比。
- MobSF：完整移动安全分析框架，作为定性对比对象，不作为离线默认 benchmark 硬依赖。

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
| HardenInspector | 6/6 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 6/6 | 1.000 | 0.400 | 0.571 | 0.450 |
| DroidLysis | 6/6 | 0.000 | 0.000 | 0.000 | 0.000 |

分类细节：

- `packer`：HardenInspector 3/3，APKiD 2/3。
- `environment`：HardenInspector 2/2，APKiD 2/2。
- `obfuscation`：HardenInspector 3/3，APKiD 0/3。
- `native`：HardenInspector 2/2，APKiD 0/2。

### 3.4 结果解释

APKiD 在 Jiagu 和 `ro.kernel.qemu` 这类信号上表现很好，说明我们的 packer 和 environment 规则与成熟开源工具的核心识别方向一致。

HardenInspector 在本数据集上覆盖更多类别，原因不是复制 APKiD，而是项目目标不同：

- APKiD 主要识别 packer/protector/obfuscator 指纹；
- HardenInspector 按中期报告要求输出三类加固技术画像和证据链；
- 本项目额外覆盖短标识符比例、反射/动态加载组合、JNI 入口等课程目标内信号。

DroidLysis 当前统计为 0，是因为本仓库未配置完整 apktool/baksmali/dex2jar 分析环境；这不代表 DroidLysis 工具本身能力不足。

## 4. 优化结论

当前实现已经在课程目标数据集上达到或超过可运行开源基线 APKiD 的类别级覆盖：

- 对 APKiD 可比的 `packer` 和 `environment` 信号，HardenInspector 均能命中；
- 对中期报告中强调但 APKiD 默认未覆盖的 evidence-chain 目标，HardenInspector 提供额外规则；
- 因此无需偏离中期报告路线去复刻 APKiD 的 YARA 规则。

后续优化方向：

- 增加更多壳库名和 StubApp 模式；
- 增加 opcode/控制流轻量统计；
- 对 Native 层引入符号表、导入表和轻量字符串上下文；
- 用真实 F-Droid/Obfuscapk/R8 构建样本扩展当前合成数据集。

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
```

验证结果：fresh venv 中 17 个测试通过，CLI 可用。

## 6. 交付物索引

| 内容 | 路径 |
| --- | --- |
| 检测器源码 | `src/hardeninspector/` |
| 数据集 | `datasets/hardeninspector_eval_v1/` |
| benchmark 统计 | `reports/benchmark/` |
| 中文文档 | `docs/` |
| 中期报告 PDF | `docs/references/mid_term.pdf` |
| 期末 Beamer | `slides/final_presentation.tex` |
| 开箱即用环境 | `Makefile`、`scripts/setup_env.sh`、`Dockerfile` |

## 7. 局限性

- 数据集是可复现合成数据集，不等价于大规模真实 APK 生态；
- 当前不实现完整 CFG、深度 Native 反汇编或动态 Frida 验证；
- 工具输出的是加固技术证据，不输出恶意/良性结论；
- benchmark 统计只证明当前数据集和类别定义下的可靠性。

## 8. 参考链接

- APKiD: https://github.com/rednaga/APKiD
- DroidLysis: https://pypi.org/project/droidlysis/
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF

