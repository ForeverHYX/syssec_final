# 使用手册

## 1. 安装

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

运行测试：

```bash
.venv/bin/pytest -q
```

## 2. 扫描 APK

文本摘要：

```bash
.venv/bin/python -m hardeninspector path/to/app.apk
```

JSON：

```bash
.venv/bin/python -m hardeninspector path/to/app.apk --json
```

写入文件：

```bash
.venv/bin/python -m hardeninspector path/to/app.apk --json -o reports/app_report.json
```

## 3. 构造演示 APK

```bash
.venv/bin/python examples/make_demo_apk.py samples/demo_hardened.apk
```

扫描：

```bash
.venv/bin/python -m hardeninspector samples/demo_hardened.apk
```

预期摘要包含：

```text
Summary: packer=4, obfuscation=2, environment=3, native=1
```

## 4. 构造评估数据集

```bash
.venv/bin/python -m hardeninspector.dataset datasets/hardeninspector_eval_v1
```

查看标签：

```bash
sed -n '1,220p' datasets/hardeninspector_eval_v1/labels.json
```

## 5. 解释输出

报告中的每条 finding 都应从 evidence 解释。

示例：

```json
{
  "id": "packer.known_library",
  "category": "packer",
  "confidence": "high",
  "evidence": [
    {
      "kind": "file",
      "location": "lib/arm64-v8a/libjiagu.so",
      "value": "libjiagu.so"
    }
  ]
}
```

解释：APK 中存在常见壳库名 `libjiagu.so`，因此命中高置信加壳库规则。

## 6. 常见问题

### 为什么某个正常应用也命中动态加载？

`DexClassLoader` 也可能用于合法插件化。需要结合 StubApp、高熵 payload、壳库名等证据综合判断。

### 为什么不直接输出“恶意/良性”？

加固技术本身是中性的。金融、游戏和企业管理应用也会使用混淆或加壳。HardenInspector 的目标是技术识别，不是恶意分类。

### 能否扫描真实 APK？

可以。工具读取 APK ZIP、Manifest、DEX 和 Native 字符串，不依赖 Android SDK。真实 APK 的复杂结构可能带来漏报，报告应作为预筛结果而不是最终结论。

