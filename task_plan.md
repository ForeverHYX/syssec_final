# syssec_final Task Plan

## Goal

Build and maintain the `syssec_final` GitHub repository for the course final exhibit: HardenInspector, a reproducible Android APK hardening detector aligned with the midterm report and the course Android track.

## Requirements Evidence

| Requirement | Source | Completion evidence |
| --- | --- | --- |
| Follow Android anti-hardening project track and choose detector direction | Course page section `3.Android应用抗加固分析` | README/spec explicitly maps to detector milestone; implementation scans APKs for hardening techniques |
| Use the midterm report as design basis | `/home/yxhong/syssec/midterm/mid_term.pdf` | Spec and implementation plan reference HardenInspector static detector architecture |
| Implement a final exhibit, not only a survey | User objective + report conclusion | Working CLI, tests, demo fixtures, JSON/text reports |
| Detect code obfuscation, packing, and environment detection techniques | Report sections 2, 6, 8 | Feature extractor and rules cover all three categories with evidence |
| Construct the datasets discussed by the report | User clarification + report section 6.8 | `datasets/hardeninspector_eval_v1/` with APKs, labels, reports, and builder |
| Provide complete Chinese documentation | User clarification | Chinese docs under `docs/` and Chinese README |
| Compare with open-source implementations and provide statistics | User clarification | Benchmark runner, comparator outputs, metrics JSON/CSV/Markdown |
| Preserve the midterm technical route and avoid copying open-source implementations | User clarification | Benchmark adapters only invoke/reference external tools; detector remains evidence-chain static rules |
| Produce final summary report and LaTeX Beamer | User clarification | `reports/final_summary.md` and `slides/final_presentation.tex` |
| Maintain an out-of-the-box environment | User clarification | Setup script, Makefile, dependency files, optional Dockerfile, fresh setup verification |
| Maintain GitHub repo named `syssec_final` | User objective | Local repo initialized, remote created/pushed, staged commits made |
| Commit and push at milestones | User objective | Git history shows staged commits and remote branch is up to date |

## Phases

### Phase 1: Repo and planning scaffold

Status: complete

- Create `syssec_final` repository.
- Add persistent planning files, report-derived spec, and implementation plan.
- Commit and push the planning milestone.

### Phase 2: Core static parser

Status: complete

- Implement APK ZIP inventory, Android binary XML string extraction, DEX string/type/method/code parsing, native string extraction, entropy helpers.
- Add tests using generated APK/DEX fixtures.
- Commit and push parser milestone.

### Phase 3: Detection rules and reporting

Status: complete

- Implement feature extraction for packer, obfuscation, environment, native signals.
- Implement rule engine and JSON/text report model.
- Add CLI entrypoint and end-to-end tests.
- Commit and push detector milestone.

### Phase 4: Demo and documentation

Status: complete

- Add Chinese README, usage guide, sample output, and final-exhibit demo steps.
- Include the midterm PDF as reference material if practical.
- Commit and push docs/demo milestone.

### Phase 5: Completion audit

Status: complete

- Run unit tests and CLI smoke tests.
- Verify git remote, commit history, and pushed branch.
- Audit every explicit user/course/report requirement before marking the goal complete.

### Phase 6: Dataset construction

Status: complete

- Add dataset builder script/module.
- Generate committed evaluation dataset with APKs, labels, and reports.
- Document dataset substitutions and sample meanings.

### Phase 7: Complete Chinese documentation

Status: complete

- Add Chinese usage guide, architecture guide, rule guide, dataset guide, demo guide, scope-change guide, and final deliverable guide.
- Link docs from README.

### Phase 8: Open-source comparison and reliability statistics

Status: complete

- Select runnable open-source comparators without changing HardenInspector's technical route.
- Implement benchmark runner and metrics.
- Run benchmark on the committed evaluation dataset.
- Optimize HardenInspector rules only where the benchmark exposes legitimate gaps against the midterm target.
- Document statistics and limitations.

### Phase 9: Final report and Beamer

Status: pending

- Produce Chinese summary report for final deliverable.
- Produce LaTeX Beamer slides for final presentation.
- Add docs links from README.

### Phase 10: New completion audit

Status: pending

- Verify tests, benchmark artifacts, report/slides, docs, git status, and remote push.
- Audit the new comparison/statistics/report requirements.

### Phase 11: Out-of-the-box environment

Status: pending

- Add dependency files and one-command setup/test/benchmark targets.
- Add optional container environment.
- Verify the setup path from a clean checkout or clean virtualenv.

## Errors Encountered

| Error | Attempt | Resolution |
| --- | --- | --- |
| Workspace root was not a git repo | `git status` in `/home/yxhong/syssec` | Created project repo under `/home/yxhong/syssec/syssec_final` |
| `pytest` missing from base environment | `pytest` and `python3 -m pytest` | Created `.venv` and installed local dev dependencies |
| DroidLysis default config writes cache under read-only home | `droidlysis --config ...` | Use `XDG_CACHE_HOME=/tmp/droidlysis_cache` in benchmark adapter |
