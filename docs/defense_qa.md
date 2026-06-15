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

### Q68：GitHub Pages 展示页讲什么？

`docs/index.html` 是给完全不了解项目的人看的入口。它按“项目定位、框架设计、报告模型、检测规则、数据集与指标、展示讲法、答辩速查、交付物索引”组织，适合答辩前快速复习，也适合作为仓库首页展示材料。

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
