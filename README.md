# HardenInspector

HardenInspector 是 `syssec_final` 期末展品的核心工具，面向课程项目 **Android 应用抗加固分析** 的“检测器”方向。

它输入 APK，静态提取 Manifest、DEX、Native 库和资源文件中的可观测证据，输出代码混淆、运行时加壳、环境检测等加固技术画像。工具不判断应用是否恶意，只输出可解释的加固证据链，供后续人工分析或课程展示使用。

## 功能

- APK ZIP 清单、文件哈希、文件熵值统计。
- Android binary XML 字符串池提取，用于读取 Manifest 中的壳入口类、权限和常量。
- 轻量 DEX 解析：字符串、类型描述符、方法表、`const-string`、`invoke-*` 和 opcode 统计。
- Native `.so` 字符串扫描，用于识别 `JNI_OnLoad`、Frida/Xposed 探测、`/proc/self/maps` 等证据。
- 规则覆盖三类课程目标：加壳、代码混淆、环境感知检测。
- 输出终端摘要或 JSON 报告，每条 finding 都包含 evidence。

## 安装与测试

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/pytest -q
```

## 使用

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
| 加壳 | 已知壳库名、Manifest StubApp、高熵 assets、动态加载 API |
| 代码混淆 | 短类名比例、反射 API/`invoke` 证据 |
| 环境检测 | emulator system properties、debugger probe、Frida/Xposed/Substrate/process maps |
| Native | `JNI_OnLoad` 等 Native 入口证据 |

## 设计依据与目标调整

- 课程题目：Android 应用抗加固分析，期末方向选择“实现一个能够检测 Android 应用使用了哪些加固技术的工具”。
- 中期报告：`Android 应用抗加固分析：代码混淆、加壳与环境检测技术的检测框架设计`，其中提出 HardenInspector 静态优先、证据链输出的方案。
- 现实调整：见 [docs/implementation_scope.md](docs/implementation_scope.md)。核心调整是不用外部样本库和动态 Frida 环境作为必需条件，优先保证检测器可运行、可测试、可复现。

## 中文文档

- [使用手册](docs/usage.md)
- [架构说明](docs/architecture.md)
- [检测规则说明](docs/rules.md)
- [数据集构造说明](docs/dataset.md)
- [开源实现对比与可靠性验证](docs/benchmark.md)
- [课程展示 Demo](docs/demo.md)
- [实现范围与目标调整说明](docs/implementation_scope.md)
- [期末交付说明](docs/final_deliverable.md)

## 局限

HardenInspector 是课程项目原型，不是工业级商业壳签名库。它输出的是静态证据和置信度，不保证完整覆盖所有加固器版本，也不把“使用加固”直接等同于恶意。
