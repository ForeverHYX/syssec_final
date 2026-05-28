# 答辩 Q&A

本文档整理期末答辩中最可能被追问的问题。回答重点是诚实说明能力边界，同时证明实现路线、测试和 benchmark 口径是可复查的。

## Q1：HardenInspector 到底检测什么？

HardenInspector 检测 APK 中可观测的加固技术证据，不做恶意/良性判定。当前四类输出是：

- `packer`：壳库名、StubApp、高熵 payload、动态加载、Native loader 符号；
- `obfuscation`：短标识符、reflection/Class.forName、控制流 opcode 密度；
- `environment`：emulator/debugger/instrumentation/telephony/native anti-debug 证据；
- `native`：`JNI_OnLoad`、`Java_*` JNI 导出符号。

## Q2：为什么不是直接用 APKiD、Androguard 或 MobSF？

课程目标是实现一个检测器。APKiD、Androguard 和 ZIP Strings 只作为比较对象：

- APKiD 偏 packer/protector/oddity 签名；
- Androguard DEX baseline 只用 DEX parser 视角，不看 Manifest/Native/resource；
- ZIP Strings 是无结构字符串扫描下限；
- DroidLysis/MobSF 需要更重外部环境，因此只做定性参照。

HardenInspector 的实现保持中期报告路线：轻量静态解析、多源特征、解释型规则和 evidence chain。

## Q3：为什么 HardenInspector Micro F1 = 1.000？会不会是过拟合？

HardenInspector Micro F1 = 1.000 是在当前 29 个合并评分样本和四类粗标签定义下得到的结果，不等价于宣称覆盖所有真实 APK。

这个分数有三层防守：

- 17 个合成 oracle APK 覆盖课程目标内的 packer、obfuscation、environment、native 关键信号；
- 12 个外部现成 APK 来自 DroidBench、F-Droid 和 PIVAA，用于扩大解析覆盖和误报审计；
- `label_basis` 逐样本记录为什么某个外部样本被映射到某类标签。

所以分数说明：在本项目定义的可复现评估集上，HardenInspector 的证据链规则与 oracle 一致。边界是：它不是大规模商业壳签名库，也不是动态分析系统。

## Q4：为什么审计 `droidbench_reflection_5` 标签？

`droidbench_reflection_5` 初始来自 DroidBench Reflection 分组，但实际可见反射 API 调用由 `android/support/v4/...` 兼容库持有，属于 support-library-only 证据。

如果继续把它标为应用混淆，ZIP Strings 这类只看 `java/lang/reflect/Method` 的浅层扫描会被奖励为正确，而 HardenInspector 的误报控制反而被扣分。标签审计后，该样本保留在外部语料中，但 `expected_categories` 为空，并在 manifest 中说明原因。

这使 benchmark 更符合项目目标：检测应用自有加固/混淆证据，而不是把第三方兼容库实现细节当作 hardening oracle。

## Q5：为什么 Web demo 需要上传扫描？

预置样本适合稳定展示，上传扫描适合现场验证工具不是写死样本结果。Web demo 的 `Scan Upload` 使用同一个 `scan_apk` pipeline：

- 浏览器把 APK bytes 发给本地服务；
- 服务端写入临时目录；
- 扫描完成后临时文件删除；
- 返回正常 JSON report；
- 默认只接受 `.apk`，大小限制 64 MiB。

这让老师可以现场指定一个 APK 文件做 smoke test。

## Q6：如果老师质疑合成数据集怎么办？

回答：

> 合成数据集用于 oracle 评分，因为它能准确控制每个样本应该触发什么 finding；外部现成 APK 用于解析覆盖、误报观察和粗粒度评分扩展。两者不是互相替代，而是分别解决“可计算 ground truth”和“真实 APK 复杂度”的问题。

同时指出仓库里保留了 APK、labels、reports、source URL、SHA-256 和生成脚本，可复现、可审计。

## Q7：当前最大局限是什么？

主要局限：

- 不做完整 CFG 恢复，只做 opcode profile 和控制流密度预筛；
- 不做深度 Native 反汇编，只解析 ELF 符号和 native strings；
- 不做动态 Frida 验证；
- 不承诺覆盖所有商业壳版本；
- 外部 APK 标签是项目级粗粒度映射，不是官方 hardening ground truth。

这些局限已经写在 `docs/implementation_scope.md` 和最终报告中。

## Q8：如果问“为什么这能拿高分”？

建议回答：

> 因为它不是只写了规则列表，而是形成了完整交付闭环：检测器、CLI、Web demo、上传扫描、合成 oracle 数据集、外部 APK 语料、四个比较对象、Precision/Recall/F1 统计、中文文档、最终报告、ZJU Beamer、自动化测试和 GitHub 提交记录。每个 finding 都能回溯到 APK 内的 evidence。

## Q9：现场最稳的演示路径是什么？

按 `docs/live_demo_script.md` 执行：

1. `make demo-web`；
2. 扫 clean baseline；
3. 扫 combined showcase；
4. 展示 Native 或 IMEI 专项样本；
5. 用 `Scan Upload` 上传一个本地 APK；
6. 展示 benchmark comparison；
7. 用终端命令兜底。
