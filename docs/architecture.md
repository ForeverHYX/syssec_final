# HardenInspector 架构说明

## 目标定位

HardenInspector 面向课程题目“Android 应用抗加固分析”的检测器方向。它解决的问题不是“这个 APK 是否恶意”，而是“这个 APK 静态上出现了哪些加固、混淆或环境检测证据”。

中期报告提出的完整框架包括解析层、特征层、决策层和可选动态验证层。期末实现保留前三层，把动态验证层作为后续扩展。

## 总体流程

```text
APK
  -> APK ZIP 清单解析
  -> Manifest string pool 提取
  -> DEX 轻量结构解析
  -> Native/资源字符串与熵值提取
  -> 归一化 Feature Model
  -> 静态规则引擎
  -> JSON/文本报告
```

## 模块划分

| 文件 | 职责 |
| --- | --- |
| `src/hardeninspector/apk.py` | 读取 APK ZIP 条目，识别 Manifest、DEX、Native 库和资源文件 |
| `src/hardeninspector/axml.py` | 提取 Android binary XML string pool 中的字符串 |
| `src/hardeninspector/dex.py` | 解析 DEX 字符串、类型、方法、class data、code item、`const-string` 和 `invoke-*` |
| `src/hardeninspector/features.py` | 将 APK/Manifest/DEX/Native 证据归一化为特征对象 |
| `src/hardeninspector/rules.py` | 执行静态规则，输出 finding 和 evidence |
| `src/hardeninspector/report.py` | 组织扫描流程并生成 JSON/文本报告 |
| `src/hardeninspector/cli.py` | 命令行入口 |
| `src/hardeninspector/synthetic.py` | 构造可复现合成 APK/DEX，用于测试、demo 和数据集 |
| `src/hardeninspector/dataset.py` | 构造期末评估数据集、labels 和每个样本的报告 |

## 为什么使用轻量解析器

中期报告建议复用 Androguard。实际落地时，核心目标是课程展示环境可复现，因此默认运行时不依赖外部库。

当前解析器只实现检测器需要的证据：

- Manifest 字符串；
- DEX 字符串、类描述符、方法名；
- `const-string` 引用的字符串；
- `invoke-*` 引用的方法；
- Native 字符串；
- 资源文件熵值。

它不是完整反编译器，也不替代 jadx、apktool 或 Androguard。

## 报告模型

每条 finding 包含：

- `id`：稳定规则 ID；
- `category`：`packer`、`obfuscation`、`environment` 或 `native`；
- `severity`：影响程度；
- `confidence`：规则置信度；
- `title` / `description`：解释；
- `evidence`：具体位置和值。

这种设计保证了展示时可以从最终标签回溯到原始 APK 证据。

