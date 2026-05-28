# 开箱即用环境

本仓库提供三种运行方式：本地 Makefile、本地 setup 脚本、Docker。

## 方式一：Makefile

```bash
make setup
make test
make dataset
make benchmark
make external-corpus
make demo
make demo-web
make slides
```

一键执行：

```bash
make all
```

## 方式二：setup 脚本

默认创建 `.venv`：

```bash
./scripts/setup_env.sh
```

指定虚拟环境目录：

```bash
./scripts/setup_env.sh /tmp/hardeninspector-venv
```

验证：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m hardeninspector --help
```

## 当前验证结果

2026-05-28 的本地与 fresh venv 复核结果：

| 命令 | 结果 |
| --- | --- |
| `.venv/bin/python -m pytest -q` | 50 个测试通过 |
| `make dataset` | 生成 18 个合成 oracle APK |
| `make benchmark` | 合成 + 外部共 30 个评分样本；四个默认评分工具均为 30/30 coverage |
| `make external-corpus` | 单独外部统计中四个工具均为 12/12 coverage |
| `make demo-web` | 启动本地网页展示，默认监听 `http://127.0.0.1:8000/`，支持预置样本和本地 APK 上传扫描 |
| `make slides` | ZJU Beamer 可编译为 22 页，构建产物由 `.gitignore` 忽略 |

## 方式三：Docker

```bash
docker build -t hardeninspector .
docker run --rm hardeninspector
```

扫描数据集样本：

```bash
docker run --rm hardeninspector \
  python -m hardeninspector datasets/hardeninspector_eval_v1/apks/combined_hardened_showcase.apk
```

## 依赖说明

- 默认 runtime：Python 标准库。
- `dev` extra：测试依赖 `pytest`。
- `benchmark` extra：评分 benchmark 使用的可运行对比依赖 `apkid` 和 `androguard`。
- `all` extra：包含测试和 benchmark 所需依赖。
- `make slides` 需要系统已安装 XeLaTeX/TeX Live 中文支持；ZJU Beamer 模板源码和图片资源已包含在 `slides/` 中，生成 PDF 与辅助文件已加入 `.gitignore`。

项目技术路线不依赖 APKiD/Androguard。它们只用于 benchmark 对比；DroidLysis/MobSF 这类需要更重外部环境的工具只在文档中作为定性参照，不进入默认评分表。
