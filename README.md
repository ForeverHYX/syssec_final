# HardenInspector

HardenInspector 是 `syssec_final` 期末展品的核心工具，面向课程项目 **Android 应用抗加固分析** 的“检测器”方向。

目标：输入 APK，静态提取 Manifest、DEX、Native 库和资源文件中的可观测证据，输出代码混淆、运行时加壳、环境检测等加固技术画像。工具不判断应用是否恶意，只输出可解释的加固证据链，供后续人工分析或展示使用。

## 当前状态

仓库正在按 `task_plan.md` 推进。最终交付会包含：

- Python CLI：`hardeninspector <apk> --json`
- JSON 报告和终端摘要
- 覆盖加壳、混淆、环境检测三类规则的测试样例
- 课程展示说明和相对中期报告的目标调整说明

## 开发

```bash
python -m pip install -e ".[dev]"
pytest -q
```

## 设计依据

- 课程题目：Android 应用抗加固分析，期末方向选择“实现一个能够检测 Android 应用使用了哪些加固技术的工具”。
- 中期报告：`Android 应用抗加固分析：代码混淆、加壳与环境检测技术的检测框架设计`，其中提出 HardenInspector 静态优先、证据链输出的方案。

