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
