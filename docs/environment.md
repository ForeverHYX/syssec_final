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
