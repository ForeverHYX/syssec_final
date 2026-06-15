.PHONY: setup test dataset benchmark external-corpus demo demo-web slides all clean

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/python -m pip
PY := $(VENV)/bin/python
HOST ?= 127.0.0.1
PORT ?= 8000

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[all]"

test:
	$(PY) -m pytest -q

dataset:
	$(PY) -m hardeninspector.dataset datasets/hardeninspector_eval_v1

benchmark:
	$(PY) -m hardeninspector.benchmark --dataset datasets/hardeninspector_eval_v1 --score-external-corpus datasets/external_apk_corpus_v1 --output reports/benchmark --tools hardeninspector apkid androguard_dex zip_string_baseline

external-corpus:
	$(PY) -m hardeninspector.benchmark --external-only --external-corpus datasets/external_apk_corpus_v1 --external-output reports/external_corpus --tools hardeninspector apkid androguard_dex zip_string_baseline

demo:
	$(PY) examples/make_demo_apk.py samples/demo_hardened.apk
	$(PY) -m hardeninspector samples/demo_hardened.apk

demo-web:
	$(PY) -m hardeninspector.demo_web --host $(HOST) --port $(PORT)

slides:
	cd slides && xelatex -interaction=nonstopmode -halt-on-error final_presentation.tex
	cd slides && xelatex -interaction=nonstopmode -halt-on-error final_presentation.tex

all: setup test dataset benchmark external-corpus demo slides

clean:
	rm -rf .pytest_cache reports/benchmark reports/external_corpus samples/demo_hardened.apk slides/*.aux slides/*.log slides/*.nav slides/*.out slides/*.snm slides/*.toc slides/*.vrb slides/*.synctex.gz slides/final_presentation.pdf
