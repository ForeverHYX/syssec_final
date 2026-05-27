# 开箱即用环境

本仓库提供三种运行方式：本地 Makefile、本地 setup 脚本、Docker。

## 方式一：Makefile

```bash
make setup
make test
make dataset
make benchmark
make demo
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
- `benchmark` extra：开源对比工具 `apkid` 和 `droidlysis`。
- `all` extra：包含测试和 benchmark 所需依赖。

项目技术路线不依赖 APKiD/DroidLysis。它们只用于 benchmark 对比。

