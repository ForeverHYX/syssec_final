# 课程展示 Demo

本文档给出可复现的期末展示流程。整个流程不需要联网下载 APK 样本。

## 1. 环境准备

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

验证测试：

```bash
.venv/bin/pytest -q
```

预期结果：

```text
53 passed
```

## 2. 生成演示 APK

```bash
.venv/bin/python examples/make_demo_apk.py samples/demo_hardened.apk
```

这个 APK 是合成样本，不包含真实恶意逻辑，只包含用于触发检测器的静态证据：

- `lib/arm64-v8a/libjiagu.so`：模拟 360 加固类壳库名；
- Manifest 字符串 `com.qihoo.util.StubApp`：模拟壳入口类；
- DEX 短类名 `La/a;`、`Lb/b;`、`Lc/c;`：模拟标识符混淆；
- DEX 字符串 `DexClassLoader`、`java.lang.reflect.Method`：模拟动态加载和反射；
- DEX 字符串 `ro.kernel.qemu`、`ro.build.fingerprint`：模拟模拟器环境检测；
- Native 字符串 `JNI_OnLoad`、`/proc/self/maps`、`frida-gadget`：模拟 JNI 和动态插桩检测。

## 3. 扫描 APK

终端摘要：

```bash
.venv/bin/python -m hardeninspector samples/demo_hardened.apk
```

JSON 报告：

```bash
.venv/bin/python -m hardeninspector samples/demo_hardened.apk --json -o reports/demo_report.json
```

## 4. 本地 Web Demo

期末展示时可以优先使用网页界面，避免现场只展示终端输出：

```bash
make demo-web
```

打开：

```text
http://127.0.0.1:8000/
```

网页会列出 clean baseline、综合加固样本、signature integrity、root artifact、Native/IMEI 专项样本和外部 APK，也支持上传本地 `.apk` 临时扫描。点击 `Scan` 或 `Scan Upload` 后会展示四类 summary 计数、finding 列表和 evidence 表，并在下方展示 `reports/benchmark/benchmark_metrics.csv` 中的 micro/macro 对比指标。接口说明见 `docs/demo_web.md`。

## 5. 展示重点

展示时建议按三条线讲解：

1. **加壳证据链**：壳库名、StubApp、动态加载 API、高熵 payload 共同说明 APK 可能存在运行时释放或加载隐藏代码的行为。
2. **混淆证据链**：短类名比例和反射调用说明静态语义被削弱，但检测器不会直接声称其为恶意。
3. **环境检测证据链**：system property、debugger、Frida/Xposed/process maps 等证据说明应用可能主动探测分析环境。

## 6. 相对中期报告的调整

详见 `docs/implementation_scope.md`。主要调整：

- 使用标准库轻量解析器替代必需 Androguard 依赖；
- 不把 Frida 动态验证作为核心交付；
- 不承诺商业加固器签名覆盖率；
- 控制流混淆已实现轻量 opcode profile 和分支/跳转密度规则，但不实现完整 CFG。

## 7. 数据集展示

期末展示还可以直接扫描已构造的数据集主样本：

```bash
.venv/bin/python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk
```

查看完整标签：

```bash
sed -n '1,220p' datasets/hardeninspector_eval_v1/labels.json
```

数据集构造方法与样本含义见 `docs/dataset.md`。
