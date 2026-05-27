# 期末交付说明

## 交付物

本仓库 `syssec_final` 包含以下期末交付内容：

- HardenInspector 静态 APK 加固技术检测器；
- 可运行 CLI；
- JSON/文本报告输出；
- 25 个自动化测试；
- 可复现评估数据集 `datasets/hardeninspector_eval_v1/`；
- 开源实现对比与统计结果：`reports/benchmark/`、`docs/benchmark.md`；
- 开箱即用环境：`Makefile`、`scripts/setup_env.sh`、`requirements*.txt`、`Dockerfile`、`docs/environment.md`；
- 中文使用手册、规则说明、架构说明、数据集说明、Demo 流程和目标调整说明；
- 期末总结报告：`reports/final_summary.md`；
- ZJU Beamer 模板期末汇报稿：`slides/final_presentation.tex`；
- 中期报告 PDF 归档：`docs/references/mid_term.pdf`；
- GitHub 远端仓库与阶段性提交记录。

## 对课程要求的覆盖

| 课程/报告要求 | 当前实现 |
| --- | --- |
| 了解代码混淆、加壳、环境检测技术 | `docs/rules.md` 和 `docs/architecture.md` 说明可观测证据与规则 |
| 选择检测器方向 | CLI 对 APK 输出加固技术画像 |
| 静态规则为核心 | `src/hardeninspector/rules.py` |
| 输出证据链 | JSON/text report 中每条 finding 都有 evidence |
| 构造小规模测试集 | `datasets/hardeninspector_eval_v1/` 包含 11 个 APK、labels 和报告 |
| 与开源实现对比并给出统计数据 | `reports/benchmark/benchmark_results.json`、`benchmark_metrics.csv`、`benchmark_summary.md`；默认评分工具均为 11/11 样本可运行，不再把 DroidLysis 不可用环境记为 0 分 |
| 开箱即用环境 | `make setup`、`./scripts/setup_env.sh`、Dockerfile；fresh venv 验证通过 |
| 总结报告和汇报材料 | `reports/final_summary.md`、ZJU Beamer `slides/final_presentation.tex`；标题为项目名，作者为中期报告组员，包含表格、TikZ 架构/指标图和一张 APK 拆解示意图，`make slides` 编译通过 |
| slides 构建产物管理 | `slides/final_presentation.pdf` 和 LaTeX 辅助文件均已加入 `.gitignore`，仅提交 `.tex`、模板 `.sty` 和模板图片资源 |
| 记录现实调整 | `docs/implementation_scope.md` |
| 课程展示可复现 | `docs/demo.md` 和 `examples/make_demo_apk.py` |

## 运行检查

```bash
.venv/bin/pytest -q
.venv/bin/python -m hardeninspector --help
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk --json
make benchmark
make slides
```

## 当前边界

- 不实现完整 CFG 或深度 Native 反汇编；
- 不把 Frida 动态验证作为必需交付；
- 不承诺商业壳签名覆盖率；
- 不将加固直接判定为恶意。

这些边界都记录在 `docs/implementation_scope.md` 中。
