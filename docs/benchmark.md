# 开源实现对比与可靠性验证

本项目使用开源实现作为验证基准，而不是改变 HardenInspector 的技术路线。检测器仍遵照中期报告：静态解析 APK/Manifest/DEX/Native，提取可解释特征，通过规则引擎输出证据链。

## 对比对象

### APKiD

APKiD 是最直接的可运行基线。其项目说明定位为 Android packer、protector、obfuscator 和 oddity identifier，并支持 JSON 输出。

项目链接：https://github.com/rednaga/APKiD

本项目使用 APKiD 3.1.0 作为主要开源基线，映射关系如下：

| APKiD 类别 | 本项目类别 |
| --- | --- |
| `packer` | `packer` |
| `obfuscator`、`anti_disassembly` | `obfuscation` |
| `anti_vm`、`anti_debug` | `environment` |

### DroidLysis

DroidLysis 是 Android 可疑样本预分析工具，会解包、反汇编并搜索可疑代码位置。它依赖 apktool、baksmali、dex2jar 等外部工具。本仓库中将其作为“可运行性/范围”对比对象：记录能否在当前环境运行，但不把缺少外部反汇编配置时的输出当作完整能力评价。

项目链接：https://pypi.org/project/droidlysis/

### MobSF

MobSF 是更完整的移动安全分析框架，覆盖静态和动态分析。它更适合作为定性对比对象；完整运行通常需要 Web 服务或 Docker 工作流，不作为本仓库默认离线 benchmark 的硬依赖。

项目链接：https://github.com/MobSF/Mobile-Security-Framework-MobSF

## 数据集

Benchmark 使用 `datasets/hardeninspector_eval_v1/`：

- 6 个合成 APK；
- 覆盖 clean baseline、环境检测、R8 风格标识符混淆、Obfuscapk 风格反射/动态加载、加壳 stub/payload、综合加固样本；
- 每个样本包含 expected findings 和当前检测器报告。

## 运行命令

```bash
.venv/bin/python -m hardeninspector.benchmark \
  --dataset datasets/hardeninspector_eval_v1 \
  --output reports/benchmark \
  --tools hardeninspector apkid droidlysis
```

输出：

- `reports/benchmark/benchmark_results.json`
- `reports/benchmark/benchmark_metrics.csv`
- `reports/benchmark/benchmark_summary.md`

## 统计结果

当前 benchmark 结果：

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 6/6 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 6/6 | 1.000 | 0.400 | 0.571 | 0.450 |
| DroidLysis | 6/6 | 0.000 | 0.000 | 0.000 | 0.000 |

解释：

- HardenInspector 在本项目数据集上达到完整 oracle 覆盖，因为数据集标签就是围绕中期报告的三类检测目标构造，且所有规则都输出证据链。
- APKiD 对 Jiagu 和 `ro.kernel.qemu` 类 anti-vm 证据表现很好，但不覆盖本项目合成数据中的短标识符比例、反射/动态加载组合和 JNI 入口这类标签。因此 recall 低于 HardenInspector。
- DroidLysis 当前没有配置 apktool/baksmali/dex2jar，benchmark 仅记录其运行状态，不把 0 分解释为工具本身能力不足。

## 可靠性结论

在本课程项目的目标范围内，HardenInspector 已经接近并覆盖 APKiD 在可比类别上的能力：

- `packer`：HardenInspector 命中 3/3，APKiD 命中 2/3。差异来自 `obfuscapk_reflection_dynamic`，本项目把动态加载作为 packer/dynamic-code-loading 证据，而 APKiD 不把它标为 packer。
- `environment`：两者都命中 2/2。
- `obfuscation`：HardenInspector 命中 3/3，APKiD 在本数据集上未命中。
- `native`：HardenInspector 额外输出 JNI 入口证据，APKiD 不覆盖该项目标签。

因此当前实现不需要为了追 APKiD 而改变路线。后续优化应继续沿中期报告路线扩展证据类型，例如更细粒度的 opcode/CFG 轻量统计、更多壳库名和 Manifest stub 模式，而不是复制 APKiD 的 YARA 规则库。

## 局限

- 数据集是合成可复现数据集，不等价于大规模真实 APK 生态。
- APKiD 的 `compiler` 类输出没有纳入本项目类别，因为 HardenInspector 的目标不是编译器识别。
- DroidLysis/MobSF 的完整能力需要更重的外部环境，本仓库默认 benchmark 保持离线、轻量、可复现。
