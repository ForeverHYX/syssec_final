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
| Use ZJU Beamer template and include tables/illustrations | User clarification | ZJU template assets in `slides/`; deck title is `HardenInspector`, authors match the midterm report, and compiled output has tables plus TikZ figures |
| Compile slides and ignore generated artifacts | User clarification | `make slides` produces a 16-page PDF; PDF and LaTeX auxiliary files are ignored by `.gitignore` |
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

Status: complete

- Produce Chinese summary report for final deliverable.
- Produce ZJU Beamer slides for final presentation.
- Include both tables and illustrations in the slides.
- Add docs links from README.

### Phase 10: New completion audit

Status: complete

- Verify tests, benchmark artifacts, report/slides, docs, git status, and remote push.
- Audit the new comparison/statistics/report requirements.

### Phase 11: Out-of-the-box environment

Status: complete

- Add dependency files and one-command setup/test/benchmark targets.
- Add optional container environment.
- Verify the setup path from a clean checkout or clean virtualenv.

### Phase 12: Benchmark fairness expansion and slide visual redesign

Status: complete

- Expand the committed synthetic dataset beyond the original six samples.
- Keep only runnable full-coverage tools in the scored benchmark table.
- Remove DroidLysis from default scoring and document it as qualitative only.
- Use LaTeX/TikZ/tables for framework, dataset, and benchmark content so text stays readable.
- Use generated imagery only for the complex APK decomposition schematic.
- Recompile and inspect the slides after the redesign.

### Phase 13: Control-flow limitation optimization and slide narrative polish

Status: complete

- Promote opcode statistics into a lightweight DEX opcode profile.
- Add `obfuscation.control_flow_density` as a reproducible control-flow-density rule.
- Add `control_flow_flattening` to the committed dataset and benchmark.
- Fix synthetic APK ZIP metadata so regenerated dataset APK bytes are stable.
- Refresh benchmark/docs/slides from 10 to 11 samples.
- Add slides that explain the final deliverable and the opcode profile without relying on generated framework images.
- Recompile and visually inspect the updated 18-page ZJU Beamer deck.

### Phase 14: External APK corpus expansion

Status: complete

- Find public ready-made APK/test-suite sources online.
- Add a committed external APK corpus with source URLs and checksums.
- Add external scan-statistics output separate from synthetic oracle F1 metrics.
- Update docs, reports, slides, and environment targets.
- Verify tests, synthetic benchmark, external corpus scan, slides, and git state.

### Phase 15: Test-result synchronization in docs and slides

Status: complete

- Synchronize latest test/benchmark/external-corpus results into README, docs, final summary, and Beamer.
- Recompile slides and inspect updated result pages.
- Re-run verification, commit, and push the documentation refresh.

### Phase 16: Include external corpus in scoring metrics

Status: complete

- Add coarse external `expected_categories` and `label_basis` entries.
- Merge the labeled external corpus into default `make benchmark` scoring.
- Regenerate benchmark reports, docs, README, and slides with 23-sample metrics.
- Re-run verification, commit, and push the scoring update.

### Phase 17: Native structural evidence and harder synthetic samples

Status: complete

- Add a lightweight ELF parser for Native symbol/import evidence.
- Detect native anti-debug/dynamic-loader symbols as environment/native findings with evidence locations.
- Add harder synthetic APK samples that rely on structural signals such as entropy and ELF symbols rather than obvious DEX strings.
- Regenerate dataset, benchmark, reports, docs, README, and slides.
- Verify locally, commit, and push.

### Phase 18: External corpus gap tuning

Status: complete

- Add coverage for `Class.forName` reflection indicators found in DroidBench.
- Add environment rules for emulator file artifacts and telephony/IMEI probes.
- Detect JNI `Java_*` exported native symbols in ELF libraries, not only `JNI_OnLoad`.
- Add synthetic samples for these patterns so the benchmark does not rely only on external APKs for regression coverage.
- Regenerate dataset, benchmark, reports, docs, README, and slides.
- Verify locally, commit, and push.

## Errors Encountered

| Error | Attempt | Resolution |
| --- | --- | --- |
| Workspace root was not a git repo | `git status` in `/home/yxhong/syssec` | Created project repo under `/home/yxhong/syssec/syssec_final` |
| `pytest` missing from base environment | `pytest` and `python3 -m pytest` | Created `.venv` and installed local dev dependencies |
| DroidLysis default config writes cache under read-only home | `droidlysis --config ...` | Use `XDG_CACHE_HOME=/tmp/droidlysis_cache` in benchmark adapter |
| DroidLysis cannot provide a fair default benchmark without external tools | default scored comparison | Removed from scored tools; APKiD, Androguard DEX, and ZIP Strings now provide full-coverage comparisons |
| Androguard initially rejected synthetic DEX files | first Androguard DEX benchmark attempt | Added DEX SHA-1 signature, Adler-32 checksum, and map list to the synthetic DEX builder |
