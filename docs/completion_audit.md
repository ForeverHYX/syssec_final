# 完成审计

审计日期：2026-05-28

## 需求覆盖

| 需求 | 证据 |
| --- | --- |
| 按课程 Android 抗加固分析题目选择检测器方向 | README 和 `docs/final_deliverable.md` 说明工具定位为 APK 加固技术检测器 |
| 参考中期报告实现期末展品 | `docs/references/mid_term.pdf` 已归档；`docs/architecture.md` 和 `docs/implementation_scope.md` 对应 HardenInspector 设计 |
| 检测代码混淆、加壳、环境检测 | `src/hardeninspector/rules.py` 覆盖 packer、obfuscation、environment、native 规则 |
| 输出证据链 | `src/hardeninspector/report.py` 的 JSON/text report 为每条 finding 输出 evidence |
| 构造报告中提到的数据集 | `datasets/hardeninspector_eval_v1/` 包含 6 个 APK、`labels.json` 和 per-sample reports |
| 提供完善中文文档 | `docs/usage.md`、`docs/architecture.md`、`docs/rules.md`、`docs/dataset.md`、`docs/demo.md`、`docs/implementation_scope.md`、`docs/final_deliverable.md` |
| 维护 GitHub repo `syssec_final` | 远端为 `git@github.com:ForeverHYX/syssec_final.git`，GitHub URL 为 `https://github.com/ForeverHYX/syssec_final` |
| 阶段性 commit | Git history 包含 planning、APK/AXML parser、DEX parser、detector CLI、docs/demo、dataset/docs 等提交 |

## 最新验证命令

```bash
.venv/bin/pytest -q
```

结果：

```text
12 passed in 0.11s
```

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

## 现存边界

- 不实现完整 CFG、深度 Native 反汇编或动态 Frida 验证。
- 不承诺覆盖所有商业加固器版本。
- 不将加固技术直接判定为恶意。

这些边界已在 `docs/implementation_scope.md` 中记录。

