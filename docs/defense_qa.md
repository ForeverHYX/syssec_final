# 答辩 Q&A 全面清单

本文档用于期末答辩准备。回答策略是：先把项目定位讲清楚，再用框架、证据链、数据集、benchmark 和测试结果证明实现是可运行、可复现、可复查的。遇到能力边界问题时不要夸大，直接说明当前范围和原因。

## 一、项目定位

### Q1：HardenInspector 到底是什么？

HardenInspector 是一个 Android APK 静态加固技术检测器。它输入 APK，解析 Manifest、DEX、Native 库和资源文件，输出加壳、代码混淆、环境检测、Native 入口等加固相关证据。

一句话版本：

> HardenInspector 不判断 APK 是否恶意，而是静态识别 APK 中可观测的加固技术证据，并输出可解释 evidence chain。

### Q2：它解决的核心问题是什么？

它解决的是“一个 APK 里出现了哪些加固、混淆或反分析证据”。传统恶意检测会给出风险结论，但本项目更关注证据来源：证据在 Manifest、DEX、Native 符号表还是资源文件里，具体值是什么，为什么能支持某个 finding。

### Q3：为什么这个题目属于 Android 应用抗加固分析？

课程题目关注代码混淆、运行时加壳和环境感知检测等抗分析技术。HardenInspector 选择“检测器”方向，检测 APK 是否出现这些技术的静态证据。它不实现加固，也不绕过加固，而是识别和解释加固迹象。

### Q4：项目和中期报告的关系是什么？

中期报告设计了解析层、特征层、决策层和可选动态验证层。期末实现保留前三层和报告层：APK/Manifest/DEX/Native/资源解析、多源特征归一化、解释型静态规则和 JSON/text evidence chain。动态验证层因为环境复杂和可复现性问题没有作为必需交付。

### Q5：为什么不做恶意/良性判断？

加固技术本身是中性的。正常商业 App 可能用加壳保护代码，恶意 App 也可能用加壳规避分析。如果直接把“加固”说成“恶意”，会造成错误结论。因此 HardenInspector 只输出证据和置信度，把最终解释留给人工分析。

### Q6：如果老师问“这不是字符串搜索吗”，怎么回答？

可以回答：字符串是证据来源之一，但不是全部。HardenInspector 还解析 Android binary XML string pool、DEX type/method/class data/code item、`const-string`、`invoke-*`、opcode profile、Native ELF `.dynsym` / `.symtab` 符号和文件熵。更重要的是，报告会保留证据位置和结构上下文，而不是只做无结构字符串匹配。

### Q7：项目最核心的贡献是什么？

核心贡献有三点：

- 实现了可运行的 APK 静态检测器，而不是只写综述；
- 建立了 Manifest + DEX + Native + 资源的多源 evidence chain；
- 构造了可复现数据集、外部 APK 语料、benchmark、Web demo、自动化测试和中文展示材料。

### Q8：为什么这能作为课程期末展品？

因为它形成了完整闭环：检测器源码、CLI、Web demo、上传扫描、22 个合成 oracle APK、12 个外部现成 APK、四个比较对象、Precision/Recall/F1 指标、69 个自动化测试、最终报告和 Beamer 汇报稿。每条 finding 都能回溯到 APK 内的 evidence。

## 二、总体架构

### Q9：系统总体流程是什么？

总体流程是：

```text
APK
  -> APK ZIP 清单解析
  -> Manifest string pool 提取
  -> DEX 轻量结构解析
  -> Native 字符串 / ELF 符号 / 资源熵值提取
  -> ApkFeatures 特征模型
  -> 静态规则引擎
  -> JSON / 文本报告 / Web demo / benchmark
```

### Q10：主要模块怎么分工？

- `apk.py`：读取 APK ZIP 条目，识别 Manifest、DEX、Native 库和资源；
- `axml.py`：提取 Android binary XML string pool；
- `dex.py`：解析 DEX 字符串、类型、方法、class data、code item、`invoke-*` 和 opcode profile；
- `native.py`：提取 Native printable strings 和 ELF 符号；
- `features.py`：把多源证据归一化为 `ApkFeatures`；
- `rules.py`：执行静态规则，生成 `Finding`；
- `report.py`：串联扫描流程，输出报告；
- `cli.py`：命令行入口；
- `demo_web.py`：本地 Web demo；
- `dataset.py` / `benchmark.py`：数据集构造和评分。

### Q11：为什么要有 `ApkFeatures` 这一层？

`ApkFeatures` 是解析层和规则层之间的边界。解析器负责理解文件格式，规则层只消费统一的字符串证据、类型描述符、方法引用、Native 符号和资源条目。这样新增规则时不需要重新理解 ZIP、DEX 或 ELF 细节。

### Q12：报告模型是什么？

报告是 `DetectorReport`，包含 APK 路径、SHA-256、entry 数量、四类 summary 和 finding 列表。每条 `Finding` 包含 `id`、`category`、`severity`、`confidence`、`title`、`description` 和 `evidence`。

### Q13：为什么每条 finding 要带 evidence？

因为加固证据需要解释。比如 `DexClassLoader` 可能是加壳，也可能是插件化；高熵 assets 可能是加密 payload，也可能是模型文件。带 evidence 后，答辩时可以指向 `location` 和 `value`，说明为什么规则命中、是否需要人工复核。

### Q14：为什么默认运行时不依赖 Androguard？

课程展示环境可能无法稳定联网安装大型依赖。HardenInspector 只需要 DEX 字符串、类型、方法、部分 opcode、Manifest 字符串、Native 符号和文件熵，因此用轻量解析器更可控、更可复现。Androguard 作为 benchmark 基线保留，用来证明 DEX 可被真实 parser 解析。

### Q15：轻量 DEX 解析器解析到了什么？

当前解析 DEX header、string IDs、type IDs、method IDs、class data 和 code item，提取 DEX strings、type descriptors、method references、`const-string`、`invoke-*` 目标和 opcode profile。它不是完整反编译器，不恢复 Java 源码或完整控制流图。

### Q16：Native 层解析到了什么？

Native 层扫描 printable strings，并解析 ELF `.dynsym` / `.symtab` 与字符串表，提取 `JNI_OnLoad`、`Java_*`、`ptrace`、`prctl`、`syscall`、`dlopen`、`android_dlopen_ext`、`dlsym` 等符号。它不做 Native 反汇编。

### Q17：为什么还要看资源熵值？

加壳或保护逻辑可能把 DEX、payload 或配置加密后放进 assets。高熵文件本身不是强结论，但可以作为 opaque payload 证据，尤其和 StubApp、壳库名、动态加载 API 一起出现时，解释力更强。

### Q18：Web demo 和 CLI 是否共用同一套逻辑？

是。CLI、预置样本扫描和上传扫描最终都调用 `scan_apk`。Web demo 只是展示层，不重新实现检测逻辑。

### Q19：上传扫描安全吗？

Web demo 是本地服务。浏览器把 APK bytes 发给本地 Python HTTP server，服务端写入临时目录，扫描完成后删除临时文件。默认只接受 `.apk`，大小限制 64 MiB，不向外部上传数据。

### Q20：这个框架怎么扩展新规则？

一般步骤是：确认证据来源，必要时在解析层增加特征；把证据放入 `ApkFeatures`；在 `rules.py` 新增解释型规则；在 `docs/rules.md` 写规则说明；构造或加入样本；补测试和 benchmark 标签。这样可以保持规则、文档和评估一致。

## 三、检测类别与规则

### Q21：当前输出哪几类？

四类：

- `packer`：运行时加壳或壳相关加载证据；
- `obfuscation`：标识符混淆、反射、控制流密度；
- `environment`：模拟器、调试器、ADB 设置、安装来源、签名完整性、root、Frida/Xposed 等环境感知检测；
- `native`：JNI 入口和 Native 导出符号。

### Q22：加壳规则有哪些？

包括已知壳库名、Manifest StubApp、高熵 assets、动态加载 API 和 Native loader 符号。例如 `libjiagu.so`、`libsecexe.so`、`StubApp`、`DexClassLoader`、`PathClassLoader`、`dlopen`、`android_dlopen_ext`。

### Q23：为什么动态加载不是 high confidence？

因为正常插件化框架也可能使用 `DexClassLoader` 或 `PathClassLoader`。动态加载是重要证据，但最好和壳库名、StubApp、高熵 payload、Native loader 符号一起解释。

### Q24：混淆规则有哪些？

包括短类名比例、反射 API / `Method.invoke` / `Class.forName` 证据，以及控制流 opcode 密度。短类名用于识别 R8/ProGuard 风格重命名；反射用于识别隐藏调用目标；控制流密度用于提示可能的控制流平坦化或跳转扰动。

### Q25：反射规则如何避免把 AndroidX/support library 误报？

当前规则过滤 `android/support`、`androidx`、Kotlin、Google Material 等常见库前缀，并要求强字面量或应用自有上下文。这个设计来自外部 APK 审计中发现的 support library 反射样板误报风险。

### Q26：`droidbench_reflection_5` 为什么要审计标签？

`droidbench_reflection_5` 初始来自 DroidBench Reflection 分组，但可见反射 API 调用由 `android/support/v4/...` 兼容库持有，属于 support-library-only 证据。如果把它算作应用混淆，浅层字符串扫描会被奖励为正确，而误报控制更严格的检测器反而被扣分。因此该样本保留在外部语料中，但 `expected_categories` 为空，并在 manifest 中说明原因。

### Q27：控制流密度规则是不是完整 CFG？

不是。它统计 code item 中 `if-*`、`goto`、switch、`throw` 等 opcode 的数量和密度，用于发现异常密集的控制流信号。它不还原真实执行路径，也不替代完整 CFG 分析。

### Q28：环境检测规则覆盖什么？

覆盖模拟器 system properties、模拟器文件痕迹、IMEI/device-id probe、ADB/developer-settings 设置探测、installer-source/sideload 安装来源探测、Java Debug API、签名完整性检查、root artifact、debugger probe、Frida/Xposed/Substrate/process maps 和 Native anti-debug 符号。

### Q29：ADB/developer settings 规则为什么要求组合证据？

单独出现 `adb` 太容易误报。规则要求同时出现 Android Settings 类名证据和具体 key，例如 `ADB_ENABLED`、`adb_enabled`、`development_settings_enabled`。这样更能说明应用在读取开发者选项或 ADB 设置。

### Q30：installer-source 规则为什么要求 API 和来源值同时出现？

单独读取包信息不一定是环境检测。规则要求出现 `getInstallerPackageName`、`getInstallSourceInfo` 或 `InstallSourceInfo` 一类 API，同时出现 `com.android.vending`、`com.android.packageinstaller`、`unknown source` 或 `adb install` 等来源指示，才输出 finding。

### Q31：Java Debug API 和 Native anti-debug 怎么区分？

Java 层规则看 `Landroid/os/Debug;` / `android.os.Debug` 与 `isDebuggerConnected`、`waitingForDebugger` 等 API。Native 层规则看 ELF 符号表中的 `ptrace`、`prctl`、`syscall`。二者来源不同，报告 evidence 位置也不同。

### Q32：root 探测如何避免匹配普通单词里的 `su`？

规则不匹配裸 `su` 子串，而是匹配 `/system/bin/su`、`/system/xbin/su`、Magisk/Superuser 包名、`RootBeer`、`test-keys`、`which su` 等更强上下文。

### Q33：签名完整性检查规则怎么判断？

规则要求同时出现 PackageManager 签名查询证据和 digest/签名处理证据，例如 `getPackageInfo`、`GET_SIGNATURES`、`SigningInfo`、`Signature`、`toByteArray`、`MessageDigest`、`SHA-256`。普通读取版本号或包名不会单独触发。

### Q34：Native 入口为什么单独成类？

Native 入口本身不一定是加固，但在 APK 加固和反分析中很常见。单独成类可以提示分析者关注 Java 与 Native 的边界，例如 JNI bridge、native loader、native anti-debug。

### Q35：规则的 severity 和 confidence 怎么理解？

`severity` 表示该信号对加固分析的重要程度，`confidence` 表示这条规则本身的确定性。例如已知壳库名通常置信度高，高熵 assets 或动态加载 API 更需要上下文，因此可能是 medium confidence。

## 四、数据集与标签

### Q36：为什么构造合成数据集？

因为真实商业加固样本存在分发权限、标签可验证性和课程展示环境问题。合成数据集能精确控制每个样本应该触发什么 finding，用于 oracle 评分和回归测试。

### Q37：合成数据集包含哪些样本？

包含 22 个 APK，覆盖 clean baseline、环境检测、Java Debug API、ADB/developer-settings、installer-source、R8 短标识符、Obfuscapk 风格反射/动态加载、两类 packer stub/payload、Native JNI bridge、Frida/Xposed、reflection-only dispatch、控制流密度、高熵 payload、Native ptrace loader、Class.forName、emulator file artifacts、IMEI probe、JNI `Java_*` 导出、signature integrity、root artifact 和 combined showcase。

### Q38：外部 APK 语料有什么作用？

外部语料包含 DroidBench、F-Droid 和 PIVAA 的 12 个现成 APK，用于扩大解析覆盖、观察真实 APK 复杂度和误报，并通过粗粒度 `expected_categories` 纳入 benchmark。

### Q39：为什么外部 APK 需要 `label_basis`？

外部 APK 的官方标签不一定等价于本项目的 hardening 类别。`label_basis` 记录为什么把某个样本映射到 packer、obfuscation、environment 或 native，避免 benchmark 标签变成不可解释黑盒。

### Q40：F-Droid 样本有什么意义？

F-Droid 样本用于低误报观察。它是正常开源 APK，如果 HardenInspector 对它没有 finding，可以说明规则不是看到真实 APK 就报风险。当前 `fdroid_editor` 已无 HardenInspector finding。

### Q41：PIVAA 样本有什么意义？

PIVAA 是外部现成漏洞训练 APK，用于证明工具能扫描非自构造样本。答辩时可以用它说明项目不只依赖 synthetic APK。

### Q42：DroidBench 样本有什么意义？

DroidBench 提供现成 Android 静态分析测试 APK。虽然它主要用于数据流/污点分析研究，但其中的反射、模拟器、Native 等样本可以作为外部解析覆盖和粗粒度标签来源。

### Q43：合成数据和外部数据之间如何分工？

合成数据解决“可计算 ground truth”；外部数据解决“真实 APK 复杂度和误报观察”。两者互补，不互相替代。

### Q44：如果老师质疑合成数据太简单怎么办？

回答：

> 合成样本用于 oracle 评分，因为每个证据都是可控植入的；外部现成 APK 用于解析覆盖和误报观察。仓库保留 APK、labels、reports、source URL、SHA-256 和生成脚本，因此评估过程可复现、可审计。

### Q45：为什么没有使用 VirusTotal 或 AndroZoo？

这些数据源存在获取权限、联网依赖、样本分发和标签验证问题，不适合课程现场复现。本项目优先保证仓库内可运行、可测试、可展示。

### Q46：数据集如何复现？

运行：

```bash
make dataset
```

或：

```bash
.venv/bin/python -m hardeninspector.dataset datasets/hardeninspector_eval_v1
```

会生成合成 APK、`labels.json` 和每个样本的 JSON report。

### Q47：标签粒度为什么是四类而不是每条规则？

Benchmark 比较对象能力不同。APKiD、Androguard DEX baseline 和 ZIP Strings 很难都映射到每条 HardenInspector 规则。四类标签能公平比较课程目标层面的 packer、obfuscation、environment、native 覆盖。

### Q48：为什么 `actual_findings` 和 `expected_findings` 都保留？

`expected_findings` 记录构造时的 oracle；`actual_findings` 记录当前检测器实际输出。测试会检查 expected 是否包含在 actual 中，防止规则回归。

## 五、Benchmark 与开源对比

### Q49：默认 benchmark 比较哪些工具？

默认比较 HardenInspector、APKiD、Androguard DEX baseline 和 ZIP Strings baseline。DroidLysis/MobSF 作为定性参照，不进入默认评分表。

### Q50：为什么 DroidLysis/MobSF 不进入默认评分？

DroidLysis 依赖 apktool、baksmali、dex2jar 等外部管线；MobSF 需要更重的服务或 Docker 工作流。如果因为环境不可用得到 0 分，会把环境问题写成工具能力问题，不公平。因此只保留定性说明。

### Q51：APKiD 在这里扮演什么角色？

APKiD 是 Android packer/protector/obfuscator/oddity identifier，是成熟开源签名工具。本项目用它作为 packer/protector 方向的比较对象，而不是实现依赖。

### Q52：Androguard DEX baseline 在这里扮演什么角色？

它证明合成 DEX 可以被真实开源 parser 解析。该 baseline 只看 DEX strings/classes/methods，不读取 Manifest、Native 或资源，因此 Native 类别 recall 预期较低。

### Q53：ZIP Strings baseline 为什么也要比？

ZIP Strings 是无结构字符串扫描下限，用来说明浅层字符串扫描在显式字符串样本上也能命中一部分信号，但缺少结构化 evidence chain，无法解释证据来自 Manifest、DEX、Native、资源还是 opcode profile。

### Q54：当前 benchmark 结果是什么？

当前合并评分集为 34 个样本，四个默认工具均为 34/34 coverage。Micro F1：

- HardenInspector：1.000；
- APKiD：0.314；
- Androguard DEX baseline：0.609；
- ZIP Strings baseline：0.759。

必须按这个口径讲：

> HardenInspector Micro F1 = 1.000 是在当前 34 个合并评分样本和四类粗标签定义下得到的结果，不等价于宣称覆盖所有真实 APK。

### Q55：为什么 HardenInspector 分数最高？

因为评分集覆盖的是本项目目标类别，而 HardenInspector 针对这些类别实现了多源结构化证据：Manifest、DEX、Native、资源熵值和规则证据链。APKiD 更偏壳/保护器签名，Androguard DEX baseline 不看 Native/Manifest/resource，ZIP Strings 不看结构上下文。

### Q56：Micro F1 = 1.000 会不会是过拟合？

要承认边界：它是当前评估集上的结果，不是大规模真实生态结论。防守点是 22 个合成 oracle APK 覆盖课程目标内核心信号，12 个外部 APK 扩大解析覆盖，标签依据和报告都在仓库中可复查。

### Q57：为什么 ZIP Strings 分数也不低？

因为合成样本故意植入可观测证据，很多证据以字符串形式存在。ZIP Strings 能抓到显式字符串，但它无法区分证据上下文，不能解析 opcode profile，也不能解析 ELF 符号表结构。真实加密或压缩样本下，浅层字符串扫描会更脆弱。

### Q58：Precision/Recall/F1 是怎么计算的？

把每个 APK 映射成四类多标签集合。对每个工具和类别统计 TP、FP、FN、TN，再计算 Precision、Recall 和 F1。Micro 指标把所有类别的 TP/FP/FN 聚合后计算，Macro 指标对各类别指标取平均。

### Q59：benchmark 怎么复现？

运行：

```bash
make benchmark
```

输出：

- `reports/benchmark/benchmark_results.json`
- `reports/benchmark/benchmark_metrics.csv`
- `reports/benchmark/benchmark_summary.md`

外部语料单独统计运行：

```bash
make external-corpus
```

### Q60：为什么 benchmark 的运行时间不是重点？

项目重点是检测能力和可解释性。报告中的 `runtime_ms` 固定为 `null`，避免毫秒级运行时间差异导致提交产物不可复现。性能可以作为工程优化方向，但不是当前课程评分核心。

## 六、演示与工程化

### Q61：现场最稳的演示路径是什么？

按 `docs/live_demo_script.md`：

1. `make demo-web`；
2. 打开 `http://127.0.0.1:8000/`；
3. 扫 clean baseline，展示低误报；
4. 扫 combined showcase，展示四类 evidence；
5. 选一个专项样本，例如 ADB 设置、安装来源、Java Debug API、root、Native ptrace 或 IMEI；
6. 使用 `扫描上传文件` 上传本地 APK；
7. 展示 benchmark comparison；
8. 用 CLI 命令兜底。

### Q62：如果浏览器打不开怎么办？

用 CLI 兜底：

```bash
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk --json
make benchmark
```

### Q63：Web demo 首屏应该讲什么？

先讲项目动机、证据链、数据集结构、34 个评分 APK、69 个测试和 HardenInspector Micro F1。然后展示样本列表、上传 APK、扫描结果 summary、finding evidence 和 benchmark 表。

### Q64：如何证明不是写死样本结果？

现场使用 `扫描上传文件` 上传一个 APK。该功能调用同一个 `scan_apk` pipeline，而不是读取预生成报告。可以上传 `combined_hardened_showcase.apk` 或老师指定的 APK 做 smoke test。

### Q65：测试覆盖了什么？

69 个自动化测试覆盖项目环境、APK/AXML 解析、DEX 解析、Native ELF 符号解析、规则命中、CLI、dataset 构造、benchmark、Web demo 接口和最终交付材料一致性。

### Q66：开箱即用环境怎么说明？

仓库提供 `Makefile`、`scripts/setup_env.sh`、`requirements*.txt` 和 `Dockerfile`。最常用命令是：

```bash
make setup
make test
make dataset
make benchmark
make external-corpus
make demo-web
```

### Q67：为什么核心依赖几乎为空？

核心检测器优先使用 Python 标准库，降低课程展示环境和离线运行风险。`pytest`、APKiD、Androguard 只在 dev/benchmark extra 中使用。

### Q68：项目说明网页讲什么？

`docs/index.html` 是给完全不了解项目的人看的入口。它按“背景概念、目标边界、总体架构、数据模型、模块设计、规则设计、数据集、benchmark、运行路径、完整 Q&A”组织，适合答辩前从零复习项目。

## 七、局限性与防守口径

### Q69：当前最大局限是什么？

主要局限：

- 不做完整 CFG 恢复；
- 不做深度 Native 反汇编；
- 不做动态 Frida 验证；
- 不承诺商业壳签名全覆盖；
- 外部 APK 标签是项目级粗粒度映射，不是官方 hardening ground truth。

### Q70：如果老师问“为什么不做动态分析”？

回答：动态分析需要模拟器、真机、Frida、Hook 脚本和运行路径触发，课程现场可复现性较差。中期报告把动态验证作为可选增强，期末交付优先完成可运行、可测试、可解释的静态检测核心。

### Q71：如果老师问“为什么不实现完整 CFG”？

回答：完整 CFG 需要更深入的 Dalvik 语义解析、异常边处理和跨方法调用关系恢复。当前实现用 opcode profile 作为轻量控制流混淆预筛，能输出可解释密度证据，但不声称还原真实执行路径。

### Q72：如果老师问“为什么 Native 不反汇编”？

回答：Native 反汇编涉及架构差异、符号剥离、优化和混淆，工程量远超课程原型。当前实现选择 ELF 符号表和字符串证据，能覆盖 `JNI_OnLoad`、`Java_*`、`ptrace`、`dlopen` 等常见可观测信号，并明确说明边界。

### Q73：如果老师问“能检测真实商业壳吗”？

回答：能检测部分可观测特征，例如常见壳库名、StubApp、动态加载、高熵 payload、Native loader 符号，但不承诺覆盖所有商业壳版本。商业壳版本变化快，样本和标签也难以公开验证。

### Q74：如果老师问“误报怎么处理”？

回答：项目从三方面控制误报：规则组合条件，例如 ADB 设置和安装来源都要求 API + key/value；库代码过滤，例如反射规则过滤 support/AndroidX/Kotlin 等前缀；低确定性证据使用 medium confidence，并在报告中保留 evidence 供人工复核。

### Q75：如果老师问“漏报怎么处理”？

回答：静态检测天然可能漏掉加密字符串、动态生成代码、强混淆 Native 逻辑和运行时触发条件。当前项目通过多源证据减少漏报：Manifest、DEX、Native 符号、资源熵值都看；但仍明确不声称全覆盖。

### Q76：如果老师问“这个项目和工业工具差距在哪”？

回答：工业工具通常有大规模样本库、商业壳签名库、动态沙箱、污点分析和 Native 反汇编能力。HardenInspector 是课程原型，优势是轻量、可复现、证据链清楚；差距是样本规模、动态能力和签名覆盖。

### Q77：如果老师问“你们为什么认为这个工作完整”？

回答：完整性体现在交付闭环，而不是声称能力无限。仓库包含检测器、CLI、Web demo、上传扫描、数据集、外部语料、benchmark、测试、文档、报告和 slides；每个结论有 evidence，每个核心规则有测试或样本支撑。

### Q78：如果老师问“最值得展示的一条 evidence 是什么”？

综合样本里可以展示 `environment.system_properties` 的 `ro.kernel.qemu`、`packer.known_library` 的壳库路径、`obfuscation.reflection` 的 `Class.forName` / `Method.invoke`、`environment.native_debugger_symbol` 的 `ptrace`，因为这些证据位置和值都直观。

### Q79：如果老师问“你个人最核心的实现点是什么”？

可以说：核心实现是把 APK 解析、DEX 轻量解析、Native ELF 符号解析和规则引擎串成统一 evidence chain，并配套构造可复现数据集和 benchmark，让展示不是停留在静态文档，而是可以现场运行。

### Q80：收尾时应该怎么说？

推荐收尾：

> HardenInspector 的价值不在于宣称能识别所有加固器，而在于把 Android 加固分析拆成可复现的静态证据链：APK 里出现了什么证据、来自哪里、支持哪类加固判断、当前评估集上如何验证。这让课程展示可以从原始 APK 一直讲到规则、报告和 benchmark。

## 八、架构设计深入追问

### Q81：为什么把系统分为解析层、特征层、规则层和报告层？

因为 APK、DEX、AXML、ELF 是不同格式，规则如果直接操作二进制细节会非常难维护。解析层负责把复杂文件格式变成结构化对象；特征层把不同来源的证据归一化；规则层只根据统一特征判断 finding；报告层负责输出 JSON、文本、网页和 benchmark 结果。这样每层职责清楚，便于解释和测试。

### Q82：如果没有 `ApkFeatures`，代码会变成什么样？

规则函数就需要自己打开 ZIP、自己解析 DEX、自己处理 ELF、自己判断字符串来自哪里。这样规则之间会重复解析逻辑，后续新增规则也容易引入不一致。`ApkFeatures` 把底层格式细节收束成一个统一接口，规则只消费 `entries`、`string_evidence`、`dex_files`、`native_symbols` 等字段。

### Q83：为什么 `StringEvidence` 要记录 `kind`？

同一个字符串来自不同位置，解释意义不同。例如 `ptrace` 出现在 DEX 字符串、Native printable string、ELF 符号表中，可信度和含义不完全一样。`kind` 可以区分 `manifest-string`、`dex-string`、`dex-const-string`、`native-string`，让报告能解释证据来源。

### Q84：为什么 `Evidence` 和 `StringEvidence` 分开？

`StringEvidence` 是特征层的原始字符串证据，规则层可以消费它。`Evidence` 是最终 finding 中展示给用户的证据，它可以来自字符串，也可以来自文件统计、DEX opcode 统计、方法表或 ELF 符号。因此二者分开能保持层次清楚。

### Q85：规则为什么是函数列表顺序执行，而不是复杂规则引擎？

课程项目需要透明、可解释、容易审计。当前规则数量有限，每条规则都是一个纯函数式判断，输入 `ApkFeatures`，输出 `Finding | None`。这种结构比引入 DSL 或复杂规则框架更容易讲清楚，也更容易写单元测试。

### Q86：规则执行顺序会影响结果吗？

目前规则之间没有共享可变状态，每条规则独立读取 `ApkFeatures` 并返回 finding。因此顺序主要影响报告中 finding 的排列，不影响是否命中。这个设计避免了规则间隐式依赖。

### Q87：为什么不在解析阶段直接打标签？

解析阶段只应该回答“APK 里有什么”，不应该回答“这是不是加固”。例如解析阶段可以提取 `DexClassLoader` 字符串，但是否把它解释为 packer 证据，应由规则层结合类别和置信度决定。这样能保持解析器通用、规则可替换。

### Q88：为什么 `DetectorReport.summary` 是按 finding 数量统计，而不是 APK 风险等级？

项目不做恶意判定，也不做风险评分。summary 只是把 finding 按四类计数，帮助展示时快速看类别分布。它不表示风险大小，也不表示加固强度的绝对量化。

### Q89：如果同一类 finding 有多个证据，为什么不把所有证据都输出？

部分规则会限制 evidence 数量，例如前 10 条，避免报告被重复字符串刷屏。完整证据在解析层仍然可以扩展保留，但展示报告需要可读性。当前目标是解释“为什么命中”，不是输出所有底层字符串。

### Q90：为什么要 dedupe evidence？

DEX 字符串表、const-string、方法引用和 Native strings 中可能重复出现同一模式。去重能减少报告噪声，让答辩时看到的是关键证据，而不是重复条目。

## 九、APK 与 Manifest 解析追问

### Q91：`apk.py` 为什么要计算每个文件的 SHA-256？

SHA-256 可以用于样本复查和报告稳定性。对外部 APK 来说，hash 能说明扫描的是同一个文件；对合成数据集来说，hash 也有助于确认样本是否被重新生成或修改。

### Q92：为什么要记录 compressed size？

当前主要展示 size、compressed size、entropy 这些文件级特征。compressed size 可以帮助观察文件是否被压缩，但当前规则主要使用原始 size 和 Shannon entropy。它保留在 `FileEntry` 中，为后续文件结构分析留下空间。

### Q93：Shannon entropy 如何用于加壳检测？

加密或压缩 payload 通常接近随机分布，熵值较高。`packer.high_entropy_payload` 对 `assets/` 中至少 128 bytes 且 entropy 不低于 7.5 的文件输出 medium confidence finding。它不是强结论，因为模型、图片、压缩包也可能高熵。

### Q94：为什么只对 `assets/` 做高熵 payload 规则？

assets 是壳或保护逻辑常放置二进制 payload 的位置。如果对所有资源无差别扫描，高熵图片、音频、压缩资源会造成更多误报。限定 assets 是为了在课程原型中控制误报。

### Q95：为什么 Manifest 只提取 string pool，不完整解析 XML？

规则需要的是 Manifest 中的字符串，例如 StubApp、壳包名前缀、应用类名、权限常量。完整 XML 树解析工程量更大，但对当前规则收益有限。提取 string pool 可以稳定拿到这些证据，符合轻量静态检测目标。

### Q96：如果 Manifest 不是标准 binary XML 怎么办？

`features.py` 中 `_extract_manifest_strings` 会先尝试 AXML string pool 提取，如果没有结果，会回退到 printable strings 提取。这是 best-effort 策略，保证异常 Manifest 不会直接让扫描失败。

### Q97：为什么 `resource_entries` 排除 `META-INF/`？

`META-INF/` 主要是签名相关文件，里面的证书或签名数据可能有较高熵，但不应该被当成加壳 payload。排除它可以降低高熵规则误报。

### Q98：APK ZIP entry 名字是否可信？

文件名本身是 APK 内部结构的一部分，可以作为静态证据，但不能单独证明行为。例如 `libjiagu.so` 是强 packer 文件名证据，而普通资源名则不能直接说明加固。规则只在明确模式上使用文件名。

## 十、DEX 解析技术追问

### Q99：DEX parser 为什么先读 header 中的 size/off 字段？

DEX 文件通过 header 指向 string_ids、type_ids、method_ids、class_defs 等区域。读取这些表的 size 和 offset 后，解析器才能按 DEX 格式定位字符串、类型、方法和 class data。

### Q100：为什么要解析 `class_data`？

仅解析方法表只能知道 APK 里有哪些方法名，但不知道方法体中实际调用了什么或引用了哪些 const-string。`class_data` 包含 direct/virtual methods 和 code offset，解析它才能进入 code item。

### Q101：为什么要解析 code item？

code item 里有 Dalvik 指令。HardenInspector 需要从中统计 opcode、提取 `const-string`、解析 `invoke-*` 目标。这些信息用于反射检测、控制流密度和环境检测 API 证据。

### Q102：`const-string` 和 DEX 字符串表有什么区别？

DEX 字符串表包含文件中所有字符串，但不一定都被某个方法实际引用。`const-string` 是方法体中实际加载字符串的指令，因此它比普通字符串表更接近代码行为证据。

### Q103：`invoke-*` 证据为什么重要？

反射和环境检测不一定只通过字符串出现。通过 `invoke-*` 可以看到某个方法体调用了 `Ljava/lang/Class;->forName` 或 `Ljava/lang/reflect/...` 方法，这比单纯字符串匹配更结构化。

### Q104：当前 DEX parser 是否支持所有 Dalvik 指令宽度？

不支持完整 Dalvik 指令集宽度。它只对当前规则关心的 opcode 做精确宽度处理，例如 `const-string`、`const-string/jumbo`、`invoke-*`、`goto`、switch、条件分支等，其余默认按 1 个 code unit 前进。这是轻量证据提取，不是完整反汇编。

### Q105：默认宽度为 1 会不会影响解析准确性？

可能影响某些不关心指令后的 cursor 对齐，因此这是当前轻量 parser 的边界。但项目构造样本和规则关注的核心指令有显式宽度处理；对于真实复杂 DEX，报告应作为静态证据提示，而不是完整反编译结论。

### Q106：为什么解析错误不直接抛出？

扫描真实 APK 时可能遇到损坏、混淆、非标准或构造异常的 DEX。如果一个 DEX 解析失败就终止整个 APK 扫描，会降低工具可用性。当前 parser 记录 `parse_errors` 并尽量返回已提取证据。

### Q107：opcode profile 是如何计算的？

解析 code item 时统计每条指令低 8 位 opcode 的出现次数。`OpcodeProfile.from_counts` 再计算总指令数、控制流指令数、控制流密度，以及 goto、if、switch、throw、invoke、const-string 等子计数。

### Q108：控制流密度阈值为什么是 instruction >= 8、control_flow >= 5、density >= 0.42？

这三个条件是为了避免小方法或普通少量分支误报。至少 8 条指令和至少 5 条控制流指令保证样本有一定规模；0.42 密度表示控制流指令占比异常高。它是预筛信号，不是完整 CFG 判断。

### Q109：为什么短类名规则要求至少 3 个类？

如果 APK 只有一两个类，短类名比例很容易偶然达到 100%。至少 3 个类可以降低小样本偶然性，再结合 60% 比例判断是否存在整体重命名趋势。

### Q110：为什么短类名阈值是长度不超过 2？

ProGuard/R8 或商业混淆常把类名压缩成 `a`、`b`、`aa` 这类短名字。长度不超过 2 是一个简单、可解释的启发式，适合课程原型展示。

## 十一、Native 与 ELF 技术追问

### Q111：为什么 Native 检测不只做 strings？

普通字符串扫描可能抓到符号名，但 ELF 符号表能提供更结构化的位置，例如 `.dynsym` 或 `.symtab`。`ptrace` 出现在 ELF symbol 中比出现在普通字符串中更适合作为 Native API 证据。

### Q112：ELF parser 支持 32 位和 64 位吗？

支持。`native.py` 根据 ELF header 的 class 字段区分 32 位和 64 位，再分别按对应 section header 和 symbol entry 格式解析。

### Q113：ELF parser 支持大小端吗？

支持基本大小端判断。它读取 ELF header 的 endian 标记，选择 `<` 或 `>` 作为 struct unpack 的 endian 前缀。

### Q114：为什么只读取 `.dynsym` 和 `.symtab`？

这两个 section 是符号表，最直接包含导出或静态符号名。当前规则只需要符号级证据，不需要 relocation、program header、反汇编或控制流分析。

### Q115：如果 Native 库被 strip，符号表没了怎么办？

符号表减少会造成漏报。当前工具还能扫描 printable strings，但深度 Native 语义分析不在当前范围内。答辩时要明确：这是符号表级 Native 证据，不是完整 Native 逆向。

### Q116：`JNI_OnLoad` 和 `Java_*` 的区别是什么？

`JNI_OnLoad` 是 Native 库被加载时 JVM 调用的入口，常用于初始化和注册 native 方法。`Java_*` 是按 JNI 命名约定导出的 Java-to-native 方法符号。二者都说明 Java 与 Native 存在执行边界。

### Q117：为什么 `native.jni_entrypoint` 是 low severity？

存在 JNI 入口不代表加固或恶意，很多正常 App 都有 Native 代码。它的价值是提示分析者关注 Native 层，因此 severity 低，但作为 evidence 仍有解释意义。

### Q118：为什么 `environment.native_debugger_symbol` 是 environment 类？

`ptrace`、`prctl`、`syscall` 这些 Native 符号常用于进程控制或反调试，它们的检测目标是调试/分析环境，因此归入 environment，而不是 native 类。

### Q119：为什么 `packer.native_dynamic_loader` 归入 packer？

Native 层 `dlopen`、`android_dlopen_ext`、`dlsym` 等符号常出现在壳 stub 或运行时 payload loader 中，因此作为 packer 相关动态加载证据。但它是 medium confidence，因为正常 Native 插件系统也可能使用这些 API。

## 十二、规则误报与漏报追问

### Q120：最容易误报的规则有哪些？

高熵 payload、动态加载、反射和控制流密度更容易误报。它们都属于 medium confidence，答辩时需要强调应结合其他证据和上下文解释。

### Q121：最稳定的规则有哪些？

已知壳库名、Manifest StubApp、Java Debug API 组合、ADB Settings API + key、installer-source API + value、ELF 符号表中的 `ptrace` 或 `JNI_OnLoad` 相对更稳定，因为它们有明确结构或组合条件。

### Q122：为什么反射规则要过滤 Android support library？

外部 APK 审计发现，support library 兼容层可能包含反射 API 调用，但这属于第三方库实现细节，不应算作应用自身混淆。过滤库上下文可以避免把正常依赖误报为 hardening。

### Q123：为什么 `droidbench_reflection_5` 标签为空更合理？

因为它的可见反射证据来自 support-library-only 上下文。如果把它标成 obfuscation，浅层字符串扫描会被奖励，而有误报控制的规则会被扣分。标签审计后更符合“应用自有加固证据”的项目目标。

### Q124：为什么不使用机器学习分类？

项目样本规模小，标签是课程级可复现 oracle，不适合训练泛化模型。解释型规则更适合当前目标：每条结论能讲清楚证据来源、命中条件和局限。

### Q125：规则阈值是怎么来的？

阈值来自课程原型场景下的可解释启发式和回归样本调优。例如高熵阈值 7.5、短类名比例 60%、控制流密度 0.42 都是为了在合成 oracle 和外部样本误报之间取得平衡。它们不是工业级统计结论。

### Q126：如果真实 APK 加密了字符串怎么办？

静态字符串和符号规则可能漏报。当前工具可以通过文件熵、壳库名、StubApp、Native loader 符号等其他证据补充，但不能保证识别所有加密样本。

### Q127：如果壳把 payload 放在非 assets 位置怎么办？

当前高熵 payload 规则可能漏报，因为它有意限制在 assets 以降低误报。可以扩展规则扫描更多目录，但需要配套误报控制和外部样本验证。

### Q128：如果 App 正常使用动态加载怎么办？

报告会输出 medium confidence finding，并保留 evidence。展示时应说这是“动态加载证据”，可能来自加壳，也可能来自插件化，不能单独判定为恶意或壳。

## 十三、数据集与 benchmark 深入追问

### Q129：为什么 benchmark 使用四类粗标签？

比较对象能力不同。APKiD、Androguard DEX baseline、ZIP Strings baseline 不可能都输出 HardenInspector 的规则 ID。四类粗标签能把不同工具映射到共同任务上，比较 packer、obfuscation、environment、native 的类别覆盖。

### Q130：Micro F1 和 Macro F1 的区别是什么？

Micro F1 汇总所有类别的 TP/FP/FN 后统一计算，更受样本和类别出现次数影响。Macro F1 先算每个类别的 F1 再平均，更能反映类别间均衡性。

### Q131：为什么 HardenInspector 在当前数据集上 F1 = 1.000？

因为当前数据集和标签就是围绕项目规则目标构造和审计的，HardenInspector 的规则与 oracle 一致。这证明当前交付闭环可靠，但不能外推到所有真实 APK。

### Q132：这是不是数据泄漏？

如果把它解释为“大规模泛化能力”，那是不严谨的。但项目明确把合成数据集作为 oracle 回归测试集，目的就是验证规则是否按设计命中。外部 APK 语料用于补充真实复杂度和误报观察。

### Q133：为什么 APKiD precision 高但 recall 低？

APKiD 擅长识别明确 packer/protector/anti-vm 签名，因此命中的通常比较准；但本项目包含大量课程构造的 environment、native、reflection、opcode-density 信号，不是 APKiD 的主要目标，所以 recall 低。

### Q134：为什么 Androguard DEX baseline native 类别为 0？

该 baseline 在本项目中只使用 DEX 视角，不读取 Native `.so`、ELF 符号和资源文件。因此它无法命中 native 类别和 Native 符号相关规则。

### Q135：为什么 ZIP Strings 在 synthetic 上表现不差？

合成样本为了可复查，很多证据是显式字符串。ZIP Strings 能抓到这些字面量。但它缺少上下文，不能区分库代码和应用代码，也不能解析 opcode 统计或 ELF 符号结构。

### Q136：外部 APK 标签是否权威？

不是。外部 APK 的 `expected_categories` 是本项目根据可见证据做的粗粒度映射，不等同于官方 hardening ground truth。因此每个外部样本都记录 `label_basis`。

### Q137：为什么 DroidLysis/MobSF 不进默认评分？

它们依赖更重的外部工具链或服务环境。如果当前环境不可用却记 0 分，会把部署问题误写成工具能力问题。本项目只把可在当前仓库环境中稳定 34/34 跑完的工具放入默认评分。

## 十四、工程实现与测试追问

### Q138：测试为什么包括最终文档检查？

课程交付不只是代码，还包括 README、报告、slides、demo 文档和答辩材料。测试最终文档可以防止样本数、测试数、关键说明过期，保证展示材料和代码状态一致。

### Q139：为什么测试中要检查 `69`？

这是当前自动化测试数量。文档、README、slides 中出现测试数量时需要同步更新，避免答辩材料写旧数字。

### Q140：为什么 Makefile 很重要？

Makefile 把常用操作标准化：setup、test、dataset、benchmark、external-corpus、demo-web、slides。答辩现场可以用固定命令复现结果，减少手动命令错误。

### Q141：为什么 Dockerfile 也保留？

Dockerfile 提供一个可选的隔离运行环境。虽然核心演示可以用本地 venv，但 Dockerfile 说明项目考虑了环境可复现性。

### Q142：为什么核心依赖为空，benchmark 依赖单独放 extra？

核心检测器要尽量离线可运行，所以默认 dependencies 为空。APKiD、Androguard、pytest 是开发和 benchmark 依赖，放在 optional extras 中，避免普通扫描安装过重依赖。

### Q143：CLI 为什么异常返回 2？

这是常见命令行约定：参数错误或运行失败返回非零。当前 CLI 捕获异常，打印 `hardeninspector: ...`，返回 2，让脚本能判断扫描失败。

### Q144：Web demo 为什么不用 Flask 或 Node？

为了减少依赖和课堂环境风险。`demo_web.py` 使用 Python 标准库 HTTP server，能离线运行，预置样本和上传扫描都调用同一套 `scan_apk`。

### Q145：静态站点部署 workflow 做了什么？

workflow 在推送 `docs/**` 或 workflow 文件变化时，把 `docs/` 作为静态站点 artifact 上传并部署为浏览器可访问的文档网页。它不构建 Python 项目，只发布文档内容。

### Q146：如果 Pages 没启用会发生什么？

`actions/configure-pages` 可能报 Pages site not found。当前仓库已启用 `build_type: workflow`，部署成功后可以直接访问 Pages URL。

### Q147：为什么网页里也要放完整 Q&A？

答辩准备时不应在多个链接之间跳转。把完整问题放在同一个页面里，可以在浏览器内搜索关键词，例如 DEX、ELF、误报、benchmark、Micro F1，快速定位回答。

### Q148：如果老师现场指定一个 APK，应该怎么演示？

优先用 Web demo 的上传扫描，说明上传只到本地服务并调用同一个 pipeline。如果浏览器不可用，用 CLI：`.venv/bin/python -m hardeninspector path/to/app.apk --json`。

### Q149：如果扫描结果为空，说明什么？

说明当前规则没有命中可观测加固证据，不说明 APK 一定没有加固，也不说明 APK 一定安全。可能是样本确实干净，也可能是使用了当前规则看不到的技术。

### Q150：如果扫描结果很多，说明什么？

说明 APK 中有多类静态证据需要关注，不等于恶意。应逐条看 evidence 的 kind、location、value，判断证据是否来自应用自有逻辑、第三方库、Native 符号或资源文件。

## 十五、讲解策略追问

### Q151：如果只能用 30 秒介绍项目，怎么说？

HardenInspector 是一个 Android APK 静态加固技术检测器。它把 APK 拆成 Manifest、DEX、Native 和资源文件，提取结构化证据，通过解释型规则输出加壳、混淆、环境检测和 Native 入口 finding。每条 finding 都能回到具体 evidence。

### Q152：如果只能用 2 分钟讲架构，怎么说？

先说输入是 APK，`apk.py` 读取 ZIP 和文件统计；`axml.py`、`dex.py`、`native.py` 分别解析 Manifest、DEX、ELF；`features.py` 统一成 `ApkFeatures`；`rules.py` 输出 `Finding`；`report.py` 生成 JSON/text；dataset 和 benchmark 复现评估。

### Q153：如果老师只关心“做了什么工程量”，怎么回答？

工程量包括轻量 APK/AXML/DEX/ELF 解析器、规则引擎、CLI、Web demo、上传扫描、合成数据集生成器、外部 APK 语料、benchmark 框架、自动化测试、最终报告、slides、Pages 文档和答辩 Q&A。

### Q154：如果老师只关心“技术深度”，怎么回答？

技术深度体现在 DEX class data/code item 解析、`const-string`/`invoke-*` 提取、opcode profile、ELF symbol table 解析、规则组合条件、误报过滤、可复现 oracle 数据集和多工具 benchmark。

### Q155：如果老师只关心“创新点”，怎么回答？

创新点不是发明新的检测算法，而是把课程目标落成可复现 evidence-chain 框架：多源解析、解释型规则、合成 oracle + 外部 APK 双数据源、对比基线和可现场运行 demo。

### Q156：如果老师追问“项目还能怎么扩展”，怎么回答？

可以增加更多真实开源样本、接入更完整的 DEX 指令宽度表、加入轻量 CFG、扩展壳签名库、解析 Native import/relocation、增加动态验证选项。但这些都应在保持 evidence chain 和测试可复现的前提下做。

### Q157：如果老师质疑“规则太人工”，怎么回答？

课程目标是检测器原型和可解释分析，人工规则更适合展示证据链。规则人工不等于随意；每条规则都有可复查条件、样本、文档和测试。机器学习需要更大规模标签数据，不适合当前交付。

### Q158：如果老师质疑“没有真实商业壳”，怎么回答？

商业壳样本存在合法获取和分发问题。本项目用可复现 synthetic oracle 替代不可公开样本，并补充 DroidBench、F-Droid、PIVAA 外部 APK 做解析覆盖。真实商业壳覆盖是工程扩展方向，不是当前承诺。

### Q159：如果老师要求现场证明可复现，先跑什么？

先跑 `.venv/bin/python -m pytest -q` 证明 69 个测试通过；再跑 `make benchmark` 证明 34 个样本和四个工具的指标可生成；最后扫一个 APK 展示 JSON evidence。

### Q160：如果最后只能留一句话，怎么说？

HardenInspector 把 Android APK 加固分析从“主观感觉像加固”变成“可复现、可定位、可解释的静态 evidence chain”。

## 十六、动态验证口径专项

### Q161：当前实现有没有引入运行时动态验证？

没有。当前交付没有启动模拟器、没有运行 APK、没有 Frida Hook、没有收集运行时日志，也没有做动态脱壳。所有 finding 都来自静态解析：APK ZIP、Manifest string pool、DEX、Native ELF 符号、Native strings 和资源熵值。

### Q162：那为什么文档里会出现“动态加载”“Frida/Xposed”“Hook”这些词？

这些是静态可观测证据，不是动态验证。例如 `DexClassLoader` 是 DEX 字符串或方法证据，`frida` / `xposed` / `/proc/self/maps` 是字符串证据，`ptrace` / `dlopen` 是 ELF 符号证据。工具只是静态识别“应用可能包含动态加载或插桩检测逻辑”，并没有实际运行这些逻辑。

### Q163：这会不会和中期报告不一致？

不冲突，但答辩时必须讲清楚。中期报告的核心主线是静态解析、特征提取和规则决策；动态验证层在报告中是“可选扩展”“若时间允许”的内容，不是期末核心交付。期末实现选择完成可运行、可复现、可测试的静态 evidence-chain 检测器，并把动态验证明确列为范围外。

### Q164：如果老师说“你中期报告写了动态验证，为什么没做”，怎么回答？

回答：

> 中期报告把动态验证设计为可选扩展层，用于在静态证据不足或冲突时做少量 Frida Hook 复核。期末实现阶段我优先保证核心检测器可运行、可复现、可测试，所以交付的是静态主路径：APK/Manifest/DEX/Native/资源解析、规则引擎、证据链报告、数据集和 benchmark。动态验证没有作为核心交付，也没有被写成当前能力。

### Q165：为什么不做动态验证是合理取舍？

动态验证依赖模拟器或真机、Frida 环境、样本启动路径、权限状态、UI 触发和反 Frida 对抗。课程展示环境下这些因素不稳定，容易导致“工具本身可行，但现场环境跑不起来”。静态检测器虽然能力边界更清楚，但更容易复现、测试和解释。

### Q166：没有动态验证会损失哪些能力？

主要损失是：不能确认某段环境检测逻辑运行时是否真的执行，不能看到加密 payload 运行时解密结果，不能捕获动态生成字符串或动态加载后的代码，也不能做真实脱壳。当前报告只能说“静态上出现证据”，不能说“运行时一定触发”。

### Q167：没有动态验证时，怎么避免报告说得太满？

用三句话约束口径：

- “检测到静态证据”，不要说“证明应用一定执行了该行为”。
- “可作为人工分析入口”，不要说“自动完成加固还原”。
- “当前评估集上验证有效”，不要说“覆盖所有真实 APK 或商业壳”。

### Q168：如果需要补一个最小动态验证模块，应该怎么设计？

最小版本可以只做可选 demo，不进入核心评分：在模拟器中运行少量自写 APK，用 Frida Hook `System.getProperty`、`Debug.isDebuggerConnected`、`ClassLoader.loadClass`、`Method.invoke`、`dlopen` 等点，收集日志并和静态 finding 对照。它应该作为“复核证据”，而不是替代静态规则。

### Q169：为什么当前 benchmark 不因为缺少动态验证而失效？

因为当前 benchmark 的任务定义就是静态证据类别识别。标签来自合成 oracle 和外部 APK 的粗粒度静态证据映射，比较对象也按静态可观测类别输出。它评估的是当前定义下的静态检测器，而不是动态脱壳系统。

### Q170：答辩时最安全的最终口径是什么？

最安全口径是：

> 当前 HardenInspector 是静态优先的 evidence-chain 检测器，没有实现运行时动态验证。中期报告中的动态验证层是可选扩展，期末交付聚焦静态主路径，并在文档中明确记录了这个范围调整。报告中所有动态相关 finding 都表示静态证据，例如动态加载 API、Frida/Xposed 探测字符串或 Native loader 符号，而不是运行时 Hook 结论。
