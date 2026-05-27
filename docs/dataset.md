# 数据集构造说明

中期报告计划使用 F-Droid、自写 APK、Obfuscapk/ProGuard/R8 处理样本，以及少量可获得的加固样本来评估检测器。期末实现保留这些类别，但为了可复现性和合法性，采用合成 APK 作为替代样本。

## 构造命令

```bash
.venv/bin/python -m hardeninspector.dataset datasets/hardeninspector_eval_v1
```

生成内容：

```text
datasets/hardeninspector_eval_v1/
  README.md
  labels.json
  apks/
    fdroid_clean_baseline.apk
    self_written_environment_checks.apk
    r8_identifier_obfuscation.apk
    obfuscapk_reflection_dynamic.apk
    packer_stub_payload.apk
    combined_hardened_showcase.apk
  reports/
    *.json
```

## 样本清单

| 样本 ID | 对应报告计划 | 构造方式 | 预期用途 |
| --- | --- | --- | --- |
| `fdroid_clean_baseline` | F-Droid baseline | 合成正常包名、可读类名、无反分析字符串 | 验证低误报基线 |
| `self_written_environment_checks` | 自写环境检测 APK | 写入 emulator/debugger 相关字符串 | 验证环境检测规则 |
| `r8_identifier_obfuscation` | ProGuard/R8 controlled obfuscation | 使用短类名 `La/a;` 等 | 验证标识符混淆规则 |
| `obfuscapk_reflection_dynamic` | Obfuscapk-style controlled obfuscation | 写入反射和动态加载字符串 | 验证反射/动态加载规则 |
| `packer_stub_payload` | packer-protected sample | 壳库名、StubApp、高熵 payload、动态加载 | 验证加壳规则 |
| `combined_hardened_showcase` | 综合加固样本 | 合并三类加固证据 | 课程展示主样本 |

## 标签格式

`labels.json` 中每个样本包含：

- `id`：样本 ID；
- `apk_path`：APK 相对路径；
- `report_path`：检测报告相对路径；
- `source_plan`：对应中期报告计划中的样本来源；
- `construction`：为什么以及如何构造；
- `expected_findings`：构造时预期命中的规则；
- `actual_findings`：当前检测器实际命中的规则；
- `actual_summary`：按类别统计的 finding 数量。

## 为什么不用真实商业样本

真实商业加固样本、VirusTotal 样本或 AndroZoo 样本存在三个问题：

- 获取和分发权限不稳定；
- 样本标签不一定能公开验证；
- 课程展示环境不一定能联网或配置 Android SDK/模拟器。

因此本仓库把“可复现数据集”作为主要交付，把真实样本扩展留作后续工作。

## 与检测器测试的关系

单元测试会在临时目录重新构造数据集，验证：

- 6 个样本全部生成；
- `labels.json` 和每个报告存在；
- 每个样本的 `expected_findings` 都包含在实际检测结果中；
- 每个合成样本都记录了它替代的原始数据来源计划。

