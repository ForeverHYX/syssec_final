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
    bangcle_stub_payload.apk
    adb_developer_settings_probe.apk
    class_forname_reflection.apk
    combined_hardened_showcase.apk
    emulator_file_artifacts.apk
    emulator_imei_probe.apk
    fdroid_clean_baseline.apk
    frida_xposed_probe.apk
    high_entropy_payload_only.apk
    native_jni_bridge_only.apk
    native_jni_export_only.apk
    native_ptrace_loader.apk
    obfuscapk_reflection_dynamic.apk
    control_flow_flattening.apk
    r8_identifier_obfuscation.apk
    packer_stub_payload.apk
    reflection_only_dispatch.apk
    root_artifact_probe.apk
    self_written_environment_checks.apk
    signature_integrity_check.apk
  reports/
    *.json
```

## 样本清单

| 样本 ID | 对应报告计划 | 构造方式 | 预期用途 |
| --- | --- | --- | --- |
| `fdroid_clean_baseline` | F-Droid baseline | 合成正常包名、可读类名、无反分析字符串 | 验证低误报基线 |
| `self_written_environment_checks` | 自写环境检测 APK | 写入 emulator/debugger 相关字符串 | 验证环境检测规则 |
| `java_debug_api_probe` | Java Debug API anti-debug sample | `Landroid/os/Debug;` + `waitingForDebugger` | 验证 Java 层反调试 API 识别 |
| `adb_developer_settings_probe` | ADB/developer-settings environment sample | `Settings$Secure` / `Settings$Global` + `ADB_ENABLED` / `development_settings_enabled` | 验证 ADB 与开发者选项系统设置探测识别 |
| `r8_identifier_obfuscation` | ProGuard/R8 controlled obfuscation | 使用短类名 `La/a;` 等 | 验证标识符混淆规则 |
| `obfuscapk_reflection_dynamic` | Obfuscapk-style controlled obfuscation | 写入反射和动态加载字符串 | 验证反射/动态加载规则 |
| `packer_stub_payload` | packer-protected sample | 壳库名、StubApp、高熵 payload、动态加载 | 验证加壳规则 |
| `bangcle_stub_payload` | Bangcle-style packer sample | Bangcle 风格壳命名、`libsecexe.so`/`libsecmain.so`、高熵 payload | 增加第二类 packer 家族 |
| `native_jni_bridge_only` | native bridge control sample | 普通 Java 层和自有 native 库 `JNI_OnLoad` | 单独验证 Native 类别 |
| `frida_xposed_probe` | instrumentation-detection sample | Frida/Xposed/Substrate/process maps 字符串 | 单独验证 instrumentation 检测 |
| `reflection_only_dispatch` | reflection-only obfuscation sample | 只包含反射 dispatch，不含动态加载 | 单独验证反射混淆 |
| `control_flow_flattening` | control-flow obfuscation sample | 构造密集 `if-*`/`goto` bytecode 模式 | 验证轻量控制流密度规则 |
| `high_entropy_payload_only` | opaque encrypted-payload control sample | 只放置高熵 asset，不植入显式加壳字符串 | 验证文件熵结构化证据 |
| `native_ptrace_loader` | native anti-debug and loader symbol sample | 构造含 `JNI_OnLoad`、`ptrace`、`android_dlopen_ext` 的 ELF `.dynsym` | 验证 Native 符号表解析 |
| `class_forname_reflection` | Class.forName reflection sample | 只放置 `Ljava/lang/Class;` + `forName` 组合证据 | 验证 Class.forName 反射识别 |
| `emulator_file_artifacts` | emulator file-artifact sample | 写入 `/proc`、`/sys`、`goldfish` 等模拟器文件/硬件痕迹 | 验证 file-based emulator detection |
| `emulator_imei_probe` | emulator IMEI probe sample | `TelephonyManager/getDeviceId` + 零值 IMEI 证据 | 验证 telephony identifier probe |
| `native_jni_export_only` | JNI Java_* export sample | ELF `.dynsym` 仅导出 `Java_*` JNI 方法，不含 `JNI_OnLoad` | 验证 JNI 导出符号识别 |
| `signature_integrity_check` | app signature integrity-check sample | PackageManager 签名查询 + `Signature/toByteArray` + `MessageDigest/SHA-256` | 验证反篡改/自完整性检测识别 |
| `root_artifact_probe` | rooted-device environment check sample | `su` 路径、Superuser/Magisk 包名、`test-keys` 和 `which su` | 验证 root/rooted-device 环境探测识别 |
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

- 21 个样本全部生成；
- `labels.json` 和每个报告存在；
- 每个样本的 `expected_findings` 都包含在实际检测结果中；
- 每个合成样本都记录了它替代的原始数据来源计划。
- 合成 DEX 带有标准 checksum、signature 和 map list，可被 Androguard DEX parser 解析，用于公平 benchmark。

## 外部 APK 补充语料

为了避免评估只停留在自构造 APK，本仓库另外维护 `datasets/external_apk_corpus_v1/`：

- 10 个 DroidBench 现成 APK；
- 1 个 F-Droid 真实开源 APK；
- 1 个 PIVAA 漏洞测试 APK。

外部 APK 已补充粗粒度 `expected_categories` 和 `label_basis`，随 `make benchmark` 进入 33 样本合并评分；`make external-corpus` 仍单独输出覆盖率和 finding 分布统计。详见 `docs/external_corpus.md`。
