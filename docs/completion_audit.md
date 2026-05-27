# 完成审计

审计日期：2026-05-28

## 需求覆盖

| 需求 | 证据 |
| --- | --- |
| 按课程 Android 抗加固分析题目选择检测器方向 | README 和 `docs/final_deliverable.md` 说明工具定位为 APK 加固技术检测器 |
| 参考中期报告实现期末展品 | `docs/references/mid_term.pdf` 已归档；`docs/architecture.md` 和 `docs/implementation_scope.md` 对应 HardenInspector 设计 |
| 检测代码混淆、加壳、环境检测 | `src/hardeninspector/rules.py` 覆盖 packer、obfuscation、environment、native 规则 |
| 输出证据链 | `src/hardeninspector/report.py` 的 JSON/text report 为每条 finding 输出 evidence |
| 构造报告中提到的数据集 | `datasets/hardeninspector_eval_v1/` 包含 10 个 APK、`labels.json` 和 per-sample reports |
| 公平 benchmark 对比 | 默认评分表只包含 10/10 样本可运行的 HardenInspector、APKiD、Androguard DEX 和 ZIP Strings；DroidLysis/MobSF 不进入评分表 |
| 提供完善中文文档 | `docs/usage.md`、`docs/architecture.md`、`docs/rules.md`、`docs/dataset.md`、`docs/demo.md`、`docs/implementation_scope.md`、`docs/final_deliverable.md` |
| 产出中文总结报告 | `reports/final_summary.md` |
| 产出期末 Beamer | `slides/final_presentation.tex` 使用 ZJU Beamer Template，标题为项目名，作者为洪奕迅、蒋城昊、项康，包含表格、TikZ 架构/指标图和一张 APK 拆解示意图 |
| slides 编译产物忽略 | `slides/final_presentation.pdf` 及 `.aux/.log/.nav/.out/.snm/.toc` 等 LaTeX 产物在 `.gitignore` 中忽略 |
| 维护 GitHub repo `syssec_final` | 远端为 `git@github.com:ForeverHYX/syssec_final.git`，GitHub URL 为 `https://github.com/ForeverHYX/syssec_final` |
| 阶段性 commit | Git history 包含 planning、APK/AXML parser、DEX parser、detector CLI、docs/demo、dataset/docs 等提交 |

## 最新验证命令

```bash
.venv/bin/python -m pytest -q
```

结果：

```text
22 passed in 0.13s
```

```bash
/tmp/hardeninspector-venv-check/bin/python -m pytest -q
```

结果：fresh venv 中 22 个测试通过。

```bash
/tmp/hardeninspector-venv-check/bin/python -m hardeninspector.benchmark --dataset datasets/hardeninspector_eval_v1 --output /tmp/hardeninspector-benchmark-check --tools hardeninspector apkid androguard_dex zip_string_baseline
```

结果：fresh venv benchmark 生成 `/tmp/hardeninspector-benchmark-check/benchmark_results.json`；HardenInspector、APKiD、Androguard DEX、ZIP Strings 均为 10/10 coverage，Micro F1 分别为 1.000、0.500、0.800、0.966。

```bash
.venv/bin/python -m hardeninspector --help
```

结果：命令退出 0，并显示 CLI 参数 `apk`、`--json`、`-o/--output`。

```bash
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/fdroid_clean_baseline.apk --json
```

结果：命令退出 0，summary 为 `packer=0`、`obfuscation=0`、`environment=0`、`native=0`。

```bash
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk --json
```

结果：命令退出 0，summary 为 `packer=4`、`obfuscation=2`、`environment=3`、`native=1`。

```bash
make benchmark
```

结果：重新生成 `reports/benchmark/`，HardenInspector Micro F1 为 1.000，APKiD 为 0.500，Androguard DEX 为 0.800，ZIP Strings 为 0.966；所有评分工具 coverage 都是 10/10。

```bash
make slides
pdfinfo slides/final_presentation.pdf
```

结果：ZJU Beamer 编译通过，PDF 为 16 页；已视觉检查背景问题、APK 拆解示意、总体架构、数据集矩阵、benchmark 公平口径和 Micro F1 图页。

```bash
git status --short --ignored slides
```

结果：`slides/final_presentation.pdf`、`.aux`、`.log`、`.nav`、`.out`、`.snm`、`.toc` 均显示为 ignored；模板 `.sty`、模板图片和 `.tex` 为源码交付物。

## 现存边界

- 不实现完整 CFG、深度 Native 反汇编或动态 Frida 验证。
- 不承诺覆盖所有商业加固器版本。
- 不将加固技术直接判定为恶意。

这些边界已在 `docs/implementation_scope.md` 中记录。
