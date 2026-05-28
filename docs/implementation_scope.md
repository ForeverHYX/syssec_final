# 实现范围与目标调整说明

本文档记录期末实现相对中期报告 HardenInspector 设想的落地范围，以及因课程周期、环境可复现性或数据获取难度而做出的调整。

## 保留并实现的核心目标

- 实现一个可运行的 APK 静态检测器，而不是停留在综述。
- 覆盖三类加固技术证据：代码混淆、运行时加壳、环境感知检测。
- 输出可解释证据链：每条规则说明命中的文件、字符串、方法名或统计特征。
- 使用本地可复现测试样本验证规则，不依赖 VirusTotal、AndroZoo 或商业样本库。
- 提供命令行工具和 JSON 报告，便于课程现场展示。

## 已实现功能清单

### APK 与基础二进制解析

- 读取 APK ZIP 文件清单、文件大小、压缩大小、SHA-256 和 Shannon 熵。
- 识别 `AndroidManifest.xml`、`classes*.dex`、`lib/**/*.so` 和资源文件。
- 从 Android binary XML string pool 中提取 Manifest 字符串。
- 从 Native `.so` 或任意二进制数据中提取 ASCII 可打印字符串。
- 从 ELF `.dynsym`/`.symtab` 和字符串表中提取 Native 符号名，作为结构化证据。

### DEX 静态证据提取

- 解析 DEX header、string IDs、type IDs、method IDs、class data 和 code item。
- 提取 DEX 字符串、类型描述符、方法名、`const-string` 引用、`invoke-*` 方法引用。
- 统计 code item 中的 opcode，用于后续轻量混淆信号。

### 规则与报告

- 加壳规则：已知壳库名、Manifest StubApp、高熵 assets、动态加载 API、Native dynamic loader 符号。
- 混淆规则：短类名比例、反射 API/`invoke`/`Class.forName` 证据、控制流 opcode 密度。
- 环境检测规则：模拟器 system properties、emulator file artifacts、IMEI/device-id probe、ADB/developer-settings probe、Java Debug API、signature integrity/self-check、root/Magisk/su artifact probe、debugger probe、Frida/Xposed/Substrate/process maps。
- Native/符号规则：`JNI_OnLoad` 入口证据、`Java_*` JNI 导出符号、Native anti-debug 符号、Native dynamic loader 符号。
- CLI 支持终端摘要、JSON 输出和 `-o/--output` 文件输出。
- `examples/make_demo_apk.py` 可生成不含真实恶意逻辑的合成展示 APK。

### 数据集

- `src/hardeninspector/dataset.py` 可一键构造 `hardeninspector_eval_v1` 数据集。
- 数据集包含 21 个 APK：F-Droid 风格基线、自写环境检测、Java Debug API 反调试、ADB/developer-settings 系统设置探测、R8 风格短标识符、Obfuscapk 风格反射/动态加载、两类加壳 stub/payload、Native JNI bridge、Frida/Xposed 探测、reflection-only dispatch、控制流密度样本、高熵 payload-only 样本、Native ptrace/loader 符号样本、Class.forName 反射样本、emulator file artifacts 样本、IMEI/device-id probe 样本、JNI `Java_*` 导出符号样本、signature integrity/self-check 样本、root/rooted-device artifact 样本、综合展示样本。
- 每个样本都有 `labels.json` 标签项和对应 JSON 检测报告。

## 调整的目标

### 1. 不把 Androguard 作为必需运行时依赖

中期报告建议复用 Androguard 解析 DEX 和 Manifest。实际实现中，MVP 改为使用 Python 标准库和轻量级自写解析器完成所需证据提取。

原因：

- 课程展示环境可能无法稳定联网安装依赖；
- 本项目只需要 DEX 字符串、类型、方法、部分 opcode 和 APK 文件清单，不需要完整反编译；
- 标准库实现更容易随仓库复现和测试。

### 2. 不实现完整动态验证层

中期报告把 Frida Hook 作为可选扩展。期末 MVP 不把动态 Hook 作为核心交付。

原因：

- Frida/模拟器/真机环境搭建耗时且不稳定；
- 课程要求选择检测器方向，静态证据链已经能展示三类加固技术识别；
- 动态层更适合作为后续增强，而不是影响核心可复现性的依赖。

### 3. 不承诺商业加固器的完备识别

工具会实现常见壳特征和高置信签名，例如 `libjiagu.so`、`StubApp`、`DexClassLoader`、高熵 assets 等，但不宣称覆盖所有商业加固器版本。

原因：

- 商业加固样本和标签难以合法、稳定、批量获取；
- 加固器版本差异大，有限样本无法支撑完备性声明；
- 课程展示重点是检测框架和可解释证据，不是工业级签名库覆盖率。

### 4. 控制流混淆只做轻量静态信号

中期报告提到控制流平坦化、垃圾代码、指令重排序等。期末实现已将 opcode 统计落成轻量 profile，并通过 `obfuscation.control_flow_density` 输出分支/跳转密度证据；仍然不构建完整 CFG。

原因：

- 完整 CFG 需要更深的 Dalvik 语义解析；
- 轻量统计足以作为“需人工复核”的可解释证据；
- 重点优先覆盖更稳定的标识符混淆、反射、动态加载和环境检测特征。

## 完成标准

期末目标完成需要满足：

- `pytest -q` 全部通过；
- `python -m hardeninspector --help` 可运行；
- 对测试 APK 可输出包含三类检测结果的 JSON；
- README 和 demo 文档能指导课程展示；
- GitHub 远端仓库 `syssec_final` 包含所有源码、测试、文档和提交历史。
