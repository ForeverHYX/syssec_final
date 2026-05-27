# Progress Log

## 2026-05-28

- Restored context from the active goal.
- Confirmed `/home/yxhong/syssec` was not a git repository and only contained `midterm/mid_term.pdf`.
- Extracted text/metadata from the midterm PDF; confirmed HardenInspector detector MVP is the report's proposed final-stage implementation.
- Opened the course project page and confirmed the Android track permits the detector direction.
- Created local project directory `/home/yxhong/syssec/syssec_final` and initialized a `main` git branch.
- Added persistent plan, findings, and progress files.
- Committed planning/skeleton milestone as `8125a0f`.
- Added `docs/implementation_scope.md` to record pragmatic changes from the midterm proposal.
- Implemented and tested APK inventory, entropy, printable strings, and binary XML string-pool extraction; committed as `264ff5d`.
- Implemented and tested a lightweight DEX parser for strings, types, methods, const-string evidence, invoke evidence, and opcode counts; committed as `08aabf9`.
- Created local `.venv` and installed `pytest` after base environment lacked pytest.
- Implemented feature extraction, static rules, report model, and CLI; committed as `b1c1640`.
- Added README, demo guide, implementation scope/change document, and reproducible demo APK generator.
- Verified demo scan: summary reported `packer=4`, `obfuscation=2`, `environment=3`, `native=1`.
- Added CLI output-directory creation after a failing test exposed the documented `-o reports/demo_report.json` path issue.
- Latest full test run: `.venv/bin/pytest -q` passed with 10 tests.
- Created dataset builder module and tests after user clarified the report's dataset plan must also be constructed.
- Generated `datasets/hardeninspector_eval_v1/` with 6 synthetic APKs, labels, and per-sample reports.
- Added complete Chinese docs for usage, architecture, rules, dataset construction, demo, implementation scope changes, and final deliverable mapping.
- Copied the midterm report PDF into `docs/references/mid_term.pdf` so the repository is self-contained.
- Ran final verification before final push: `.venv/bin/pytest -q` passed with 12 tests; CLI help exited 0; clean baseline sample produced zero findings; combined showcase sample produced `packer=4`, `obfuscation=2`, `environment=3`, `native=1`.
- Added `docs/completion_audit.md` with requirement-by-requirement evidence.

## 2026-05-28 Benchmark Extension

- User added a new objective: compare with open-source implementations, provide reliability statistics, keep optimizing, maintain docs/readme, and produce final summary report plus LaTeX Beamer.
- Looked up primary sources for APKiD, DroidLysis, and MobSF. APKiD is directly relevant as an Android packer/protector/obfuscator identifier; DroidLysis is a pre-analysis tool for suspicious Android samples; MobSF is a broader static/dynamic mobile analysis framework.
- Installed APKiD 3.1.0 and DroidLysis 3.4.7 into `.venv` for local comparator runs.
- Ran APKiD on `datasets/hardeninspector_eval_v1/apks/*.apk`; it detected `Jiagu` packer on the two shell-like samples and `ro.kernel.qemu check` on the two environment-check samples, but not the synthetic R8/Obfuscapk-style samples.
- Ran DroidLysis help and a smoke run. It requires external disassembly tools for full analysis; with package defaults it can run only with `XDG_CACHE_HOME=/tmp/droidlysis_cache` and warns about missing apktool/baksmali/dex2jar paths.
- User clarified the final repo must also maintain an out-of-the-box environment. This is now tracked as setup automation, dependency files, optional Docker environment, and fresh setup verification.
- Added `src/hardeninspector/benchmark.py` and tests for category-level multilabel precision/recall/F1.
- Generated benchmark artifacts under `reports/benchmark/`: JSON, CSV, and Markdown summary. Current category-level micro F1: HardenInspector 1.000, APKiD 0.571, DroidLysis 0.000 in limited local mode.
- Added `docs/benchmark.md` explaining comparator scope, metrics, and why open-source tools are validation baselines rather than the implementation route.
- Added out-of-the-box environment files: `Makefile`, `scripts/setup_env.sh`, `requirements*.txt`, `Dockerfile`, and `docs/environment.md`.
- Verified fresh setup path with `/tmp/hardeninspector-venv-check`: setup script installed `[all]` dependencies, `/tmp/hardeninspector-venv-check/bin/python -m pytest -q` passed with 17 tests, and `/tmp/hardeninspector-venv-check/bin/python -m hardeninspector --help` exited 0.
- Added `reports/final_summary.md` Chinese final report and `slides/final_presentation.tex` LaTeX Beamer deck.
- Verified Beamer compilation with `xelatex -interaction=nonstopmode -halt-on-error -output-directory=/tmp slides/final_presentation.tex`; output was `/tmp/final_presentation.pdf` with 12 pages.
- User requested the final slides use the ZJU Beamer template, keep the project name as the title, use member names from the midterm report, include both tables and illustrations, compile and inspect the deck, and ignore generated slide artifacts.
- Imported ZJU Beamer Template assets into `slides/` with attribution in `slides/README.md`.
- Rebuilt `slides/final_presentation.tex` on the ZJU template with title `HardenInspector`, authors 洪奕迅、蒋城昊、项康, rule/benchmark tables, a pipeline diagram, a dataset-construction diagram, and a Micro F1 visualization.
- Updated `Makefile` so `make slides` compiles from `slides/` twice, matching the template's relative asset paths and stabilizing total frame count.
- Added slide build artifacts to `.gitignore`: PDF plus LaTeX `.aux/.log/.nav/.out/.snm/.toc/.vrb` and related files.
- Compiled the ZJU Beamer deck with `make slides`; `pdfinfo` reported 14 pages.
- Rendered and visually inspected representative pages: title page, architecture diagram, benchmark table, and Micro F1 chart.
- Made benchmark JSON reproducible by serializing `runtime_ms` as `null`, added a regression test, and regenerated `reports/benchmark/benchmark_results.json`.
- Latest local and fresh-venv test runs passed with 22 tests.
- Committed and pushed the ZJU Beamer/report/artifact-ignore milestone as `62f7b53`.

## 2026-05-28 Benchmark Fairness Expansion

- User requested a more complete benchmark, larger dataset, and removal/fix of unusable DroidLysis-style comparisons.
- Added tests requiring the default benchmark tools to exclude DroidLysis and include only runnable scored comparators.
- Expanded the evaluation dataset from 6 to 10 synthetic APKs with additional Bangcle-style packer, native-only JNI bridge, Frida/Xposed probe, and reflection-only samples.
- Updated synthetic DEX generation with standard SHA-1 signature, Adler-32 checksum, and map list so Androguard can parse the DEX files.
- Replaced the scored DroidLysis comparator with two usable baselines: Androguard DEX parser baseline and ZIP Strings shallow baseline.
- Removed DroidLysis from benchmark dependencies; `benchmark`/`all` extras now install APKiD and Androguard.
- Regenerated `datasets/hardeninspector_eval_v1/` and `reports/benchmark/`; all scored comparators have 10/10 sample coverage.
- User clarified that generated images should be reserved for complex explanatory schematics, not for all framework/benchmark content.
- Reworked the ZJU Beamer deck so framework, dataset matrix, benchmark fairness, and Micro F1 are rendered as readable LaTeX/TikZ/table content.
- Generated one text-free APK static-analysis cutaway image with the built-in image generation tool and copied it into `slides/figures/apk_static_analysis_cutaway.png`; it is used only as a visual aid for understanding APK decomposition.
- Recompiled the redesigned ZJU Beamer deck with `make slides`; `pdfinfo` reports 16 pages, and rendered checks of pages 3, 5, 6, 9, 10, and 12 show readable text and the expected image/table/TikZ balance.
- Reran local verification after the benchmark expansion: `.venv/bin/python -m pytest -q` passed with 22 tests; `make dataset` regenerated 10 samples; `make benchmark` reported 10/10 coverage for HardenInspector, APKiD, Androguard DEX, and ZIP Strings.
- Updated `/tmp/hardeninspector-venv-check` with `pip install -e ".[all]"`; the first sandboxed install failed due proxy network restrictions, then the escalated install succeeded.
- Fresh venv verification passed: `/tmp/hardeninspector-venv-check/bin/python -m pytest -q` passed with 22 tests, and the fresh benchmark run under `/tmp/hardeninspector-benchmark-check` kept all four default tools at 10/10 coverage.
- `git diff --check` produced no whitespace errors; `git status --short --ignored slides` confirms the compiled PDF and LaTeX auxiliary files are ignored while the source `.tex` and generated APK cutaway PNG asset remain trackable.
