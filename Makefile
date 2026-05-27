.PHONY: setup test dataset benchmark demo all clean

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/python -m pip
PY := $(VENV)/bin/python

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[all]"

test:
	$(PY) -m pytest -q

dataset:
	$(PY) -m hardeninspector.dataset datasets/hardeninspector_eval_v1

benchmark:
	$(PY) -m hardeninspector.benchmark --dataset datasets/hardeninspector_eval_v1 --output reports/benchmark --tools hardeninspector apkid droidlysis

demo:
	$(PY) examples/make_demo_apk.py samples/demo_hardened.apk
	$(PY) -m hardeninspector samples/demo_hardened.apk

all: setup test dataset benchmark demo

clean:
	rm -rf .pytest_cache reports/benchmark samples/demo_hardened.apk

