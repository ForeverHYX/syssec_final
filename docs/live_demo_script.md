# 现场演示脚本

这份脚本用于期末展示现场，目标是在 5 到 8 分钟内证明 HardenInspector 是可运行、可解释、可复现的 APK 加固技术检测器。

## 1. 开场定位

一句话说明：

> HardenInspector 不判断 APK 是否恶意，而是静态识别 APK 中可观测的加壳、混淆、环境检测和 Native 入口证据，并输出 evidence chain。

强调三点：

- 对齐中期报告路线：APK/Manifest/DEX/Native/资源解析，加解释型规则；
- 保持离线可复现：核心检测器只依赖 Python 标准库；
- 不复制开源工具：APKiD、Androguard、ZIP Strings 是比较对象，不是实现来源。

## 2. 启动网页

```bash
make demo-web
```

打开：

```text
http://127.0.0.1:8000/
```

先展示页面结构：

- 顶部 `Exhibit Map`：说明项目动机、证据链、数据集结构、31 个评分 APK、54 个测试和 HardenInspector Micro F1；
- 左侧 curated samples；
- `Upload APK` 和 `Scan Upload`；
- 右侧 summary、finding、Evidence 表；
- 下方 benchmark comparison。

## 3. 演示 clean baseline

选择 `F-Droid clean synthetic baseline`，点击 `Scan`。

讲解重点：

- 四类 summary 都是 0；
- 说明检测器不是看到 APK 就报风险；
- 对应真实外部样本 `fdroid_editor` 也无 HardenInspector finding。

## 4. 演示综合加固样本

选择 `Combined hardened showcase`，点击 `Scan`。

讲解顺序：

1. `packer`：壳库名、StubApp、高熵 payload、动态加载；
2. `obfuscation`：短标识符和 reflection evidence；
3. `environment`：system property、debugger、instrumentation 相关证据；
4. `native`：JNI 入口或导出符号。

每一类都点开 Evidence 表，说明 location 和 value 是可复查证据，不是黑盒分数。

## 5. 演示专项样本

建议二选一：

- `Signature integrity check`：展示 PackageManager 签名 API 与 `MessageDigest/SHA-256` 组合形成的反篡改 evidence；
- `Root artifact probe`：展示 `su` 路径、Superuser/Magisk 包名和 `test-keys` 组成的 root 环境 evidence；
- `Native ptrace and loader signals`：展示 ELF 符号表证据，说明 Native 不只是字符串扫描；
- `Emulator IMEI probe`：展示 telephony/device-id emulator probe。

如果老师关注真实 APK，选择 `PIVAA training APK`，说明它是外部现成 APK，用来证明工具能处理非自造样本。

## 6. 演示上传扫描

点击 `Upload APK`，选择仓库中的一个 APK，例如：

```text
datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk
```

点击 `Scan Upload`。

讲解重点：

- 上传只发送到本地 demo server；
- 临时文件扫描完成后删除；
- 使用同一个 `scan_apk` pipeline；
- 不需要联网、不需要 Android SDK。

## 7. 展示 benchmark

页面下方或 README 中展示当前合并评分：

| Tool | Coverage | Micro F1 |
| --- | ---: | ---: |
| HardenInspector | 31/31 | 1.000 |
| APKiD | 31/31 | 0.333 |
| Androguard DEX | 31/31 | 0.571 |
| ZIP Strings | 31/31 | 0.740 |

说明 `droidbench_reflection_5` 标签审计：它的可见反射证据是 support-library-only，所以不再作为应用混淆 oracle。这样避免把浅层字符串误报奖励成正确结果。

## 8. 终端兜底命令

如果浏览器不可用，直接运行：

```bash
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk --json
make benchmark
make external-corpus
```

## 9. 收束

最后一句：

> 这个项目的核心价值是可复现的静态 evidence chain：每条结论都能回到 APK 里的 Manifest、DEX、Native 或资源证据，并且通过 19 个合成 oracle APK、12 个外部现成 APK 和 54 个自动化测试持续验证。
