# HardenInspector

HardenInspector 是 `syssec_final` 期末展品的核心工具，面向课程项目 **Android 应用抗加固分析** 的“检测器”方向。

它输入 APK，静态提取 Manifest、DEX、Native 库和资源文件中的可观测证据，输出代码混淆、运行时加壳、环境检测等加固技术画像。工具不判断应用是否恶意，只输出可解释的加固证据链，供后续人工分析或课程展示使用。

## 功能

- APK ZIP 清单、文件哈希、文件熵值统计。
- Android binary XML 字符串池提取，用于读取 Manifest 中的壳入口类、权限和常量。
- 轻量 DEX 解析：字符串、类型描述符、方法表、`const-string`、`invoke-*`、opcode profile 和控制流密度统计。
- Native `.so` 字符串与 ELF 符号表扫描，用于识别 `JNI_OnLoad`、`ptrace`、`dlopen`/`android_dlopen_ext`、Frida/Xposed 探测、`/proc/self/maps` 等证据。
- 规则覆盖三类课程目标：加壳、代码混淆、环境感知检测。
- 输出终端摘要或 JSON 报告，每条 finding 都包含 evidence。

## 安装与测试

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest -q
```

也可以直接使用仓库维护的 Makefile：

```bash
make setup
make test
make dataset
make benchmark
make external-corpus
make demo-web
make slides
```

默认 benchmark 现在把 17 个合成 oracle APK 和 12 个外部现成 APK 合并评分，共 29 个样本。评分表只包含当前环境可安装、可运行且 29/29 样本都有输出的比较对象：HardenInspector、APKiD、Androguard DEX baseline 和 ZIP Strings baseline。DroidLysis/MobSF 不进入默认评分表，避免把缺少外部分析管线造成的不可用结果记成 0 分。

外部 APK 语料位于 `datasets/external_apk_corpus_v1/`，包含 DroidBench、F-Droid 和 PIVAA 的 12 个现成 APK。`manifest.json` 记录粗粒度 `expected_categories` 和 `label_basis`，用于合并 benchmark 评分；`make external-corpus` 仍单独输出覆盖率和 finding 分布。

## 最新测试结果

2026-05-28 的最终验证结果：

| 项目 | 结果 |
| --- | --- |
| 自动化测试 | `46 passed` |
| 合并评分数据集 | 17 个 synthetic APK + 12 个外部 APK，四个默认评分工具均为 29/29 coverage |
| Combined benchmark Micro F1 | HardenInspector 1.000；APKiD 0.348；Androguard DEX 0.517；ZIP Strings 0.716 |
| 外部现成 APK 语料 | 已纳入评分；单独统计中四个工具仍为 12/12 coverage |
| 外部语料 HardenInspector 分布 | Any 10/12；packer=4；obfuscation=2；environment=5；native=3；F-Droid 样本无 finding |
| Slides | ZJU Beamer 可通过 `make slides` 编译为 21 页，PDF/aux/log 等构建产物已忽略 |

## 使用

启动本地网页展示：

```bash
make demo-web
```

浏览器访问 `http://127.0.0.1:8000/`。页面可以选择 clean baseline、综合加固样本、Native/IMEI 专项样本和外部 APK，也可以上传本地 APK 临时扫描，现场查看 summary、finding evidence 和 benchmark 对比指标。

生成可复现演示 APK：

```bash
.venv/bin/python examples/make_demo_apk.py samples/demo_hardened.apk
```

输出可读摘要：

```bash
.venv/bin/python -m hardeninspector samples/demo_hardened.apk
```

输出 JSON：

```bash
.venv/bin/python -m hardeninspector samples/demo_hardened.apk --json
```

报告中的 finding 示例：

```json
{
  "id": "environment.system_properties",
  "category": "environment",
  "confidence": "high",
  "evidence": [
    {
      "kind": "dex-string",
      "value": "ro.kernel.qemu",
      "location": "classes.dex:string"
    }
  ]
}
```

## 规则类别

| 类别 | 已实现信号 |
| --- | --- |
| 加壳 | 已知壳库名、Manifest StubApp、高熵 assets、动态加载 API、Native loader 符号 |
| 代码混淆 | 短类名比例、反射 API/`invoke`/`Class.forName` 证据、分支/跳转 opcode 密度 |
| 环境检测 | emulator system properties、emulator file artifacts、IMEI/device-id probe、debugger probe、Native anti-debug 符号、Frida/Xposed/Substrate/process maps |
| Native | `JNI_OnLoad` 与 `Java_*` JNI 导出符号等 Native 入口证据 |

## 设计依据与目标调整

- 课程题目：Android 应用抗加固分析，期末方向选择“实现一个能够检测 Android 应用使用了哪些加固技术的工具”。
- 中期报告：`Android 应用抗加固分析：代码混淆、加壳与环境检测技术的检测框架设计`，其中提出 HardenInspector 静态优先、证据链输出的方案。
- 现实调整：见 [docs/implementation_scope.md](docs/implementation_scope.md)。核心调整是不用商业壳样本和动态 Frida 环境作为必需条件，优先保证检测器可运行、可测试、可复现；公开现成 APK 已作为补充语料纳入扫描统计。

## 中文文档

- [使用手册](docs/usage.md)
- [架构说明](docs/architecture.md)
- [检测规则说明](docs/rules.md)
- [数据集构造说明](docs/dataset.md)
- [外部 APK 语料说明](docs/external_corpus.md)
- [开源实现对比与可靠性验证](docs/benchmark.md)
- [开箱即用环境](docs/environment.md)
- [课程展示 Demo](docs/demo.md)
- [本地 Web Demo](docs/demo_web.md)
- [实现范围与目标调整说明](docs/implementation_scope.md)
- [期末交付说明](docs/final_deliverable.md)
- [期末总结报告](reports/final_summary.md)
- [ZJU Beamer 汇报稿](slides/final_presentation.tex)

## 局限

HardenInspector 是课程项目原型，不是工业级商业壳签名库。它输出的是静态证据和置信度，不保证完整覆盖所有加固器版本，也不把“使用加固”直接等同于恶意。
