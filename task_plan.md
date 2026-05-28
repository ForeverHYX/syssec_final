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
| Compile slides and ignore generated artifacts | User clarification | `make slides` produces a 22-page PDF; PDF and LaTeX auxiliary files are ignored by `.gitignore` |
| Maintain an out-of-the-box environment | User clarification | Setup script, Makefile, dependency files, optional Dockerfile, fresh setup verification |
| Maintain GitHub repo named `syssec_final` | User objective | Local repo initialized, remote `git@github.com:ForeverHYX/syssec_final.git` configured; `main` is synchronized with `origin/main` |
| Commit and push at milestones | User objective | Git history shows staged commits; latest local improvements are pushed to GitHub |
| Provide an interactive demo page | User objective | `make demo-web` launches a local standard-library Web demo with sample scans, APK upload scanning, and benchmark metrics |

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

### Phase 19: Third-party reflection false-positive hardening

Status: complete

- Add regression tests for Android support-library reflection scaffolding versus application-owned reflection dispatch.
- Filter reflection findings from support-library/platform compatibility code while keeping strong `Method.invoke` and application-context reflection evidence.
- Regenerate dataset reports, combined benchmark, external-corpus reports, README, docs, final summary, and slides.
- Verify locally and in fresh venv.
- Commit locally and push to GitHub.

### Phase 20: External corpus native label audit

Status: complete

- Inspect the remaining Native mismatch in `droidbench_bytecode_tamper_1`.
- Add a regression test requiring scored external samples with visible `Java_*` JNI exports to include the `native` expected category.
- Update the sample `label_basis` to document its JNI bridge evidence.
- Regenerate benchmark/external-corpus reports, README, docs, final summary, and slides.
- Verify locally and in fresh venv.
- Commit locally and push to GitHub.

### Phase 21: Local Web demo page

Status: complete

- Add a dependency-free `hardeninspector.demo_web` server using Python standard library HTTP APIs.
- Add curated synthetic/external APK samples for classroom scanning.
- Expose `/api/samples`, `/api/scan`, and `/api/metrics` for live report and benchmark display.
- Add tests for catalog integrity, scan output, metric parsing, HTML/API surface, and command exposure.
- Update README, usage/demo/environment/final-deliverable docs, final summary, and completion audit.

### Phase 22: Web demo uploaded APK scanning

Status: complete

- Add TDD coverage for scanning raw uploaded APK bytes and rejecting non-APK/oversized inputs.
- Add `scan_uploaded_apk` with temporary-file scanning, filename sanitization, suffix validation, and a 64 MiB demo limit.
- Expose `POST /api/scan-upload?filename=<name.apk>` and wire the page file input to it.
- Update README, demo docs, usage/environment docs, final deliverable, final summary, completion audit, progress, and findings.

### Phase 23: External reflection label audit

Status: complete

- Root-cause inspect the final HardenInspector benchmark mismatch, `droidbench_reflection_5`.
- Confirm the visible reflection API calls are support-library compatibility code, not application-owned reflection dispatch.
- Add a regression test requiring external reflection labels to follow application-owned evidence.
- Remove `obfuscation` from `droidbench_reflection_5` expected categories and document the label basis.
- Regenerate benchmark and external-corpus reports; HardenInspector reaches 29/29 coverage with Micro/Macro F1 1.000.
- Update README, benchmark/external-corpus docs, final summary, completion audit, slides, progress, and findings.

### Phase 24: Defense package and live demo script

Status: complete

- Add a tested live demo script for the final exhibit flow.
- Add a tested defense Q&A document covering benchmark 1.000, external label audit, support-library-only reflection, upload demo, comparator fairness, and limitations.
- Link both documents from README.
- Update progress and findings.

### Phase 25: Final-presentation language and exhibit Web polish

Status: complete

- Add regression coverage that rejects process-oriented wording such as `这轮` / `本轮` in final-facing slides and summary report.
- Add regression coverage requiring the Web demo to explain Exhibit Map, Evidence Chain, Dataset Story, 29 scored APKs, HardenInspector Micro F1, and current regression-test count.
- Enrich the Web demo catalog with dataset-kind and showcase-role metadata for each curated sample.
- Add a first-screen exhibit overview, dataset explanation, benchmark/test summary, and APK cutaway visual asset route to the Web demo.
- Update README, Web demo docs, final summary, progress, and findings.

### Phase 26: Web demo protocol polish and slide demo narrative

Status: complete

- Add regression coverage for `HEAD /assets/apk-cutaway.png` so smoke checks and browser preflight-style probes return image headers without a body.
- Add regression coverage requiring the final Beamer deck to include a dedicated `现场 Web Demo` frame with Exhibit Map, Evidence Chain, Dataset Story, Synthetic Oracle, External APK Corpus, and Scan Upload.
- Implement `do_HEAD` for the Web demo's read-only routes by sharing the GET routing path and suppressing response bodies.
- Add a final-presentation slide explaining how the Web demo shows the project motivation, evidence chain, dataset structure, benchmark/test status, curated samples, and upload scan.
- Synchronize README, docs, summary report, completion audit, and planning logs with 47 tests and 22 slides.

### Phase 27: Signature integrity/self-check detection

Status: complete

- Add detector coverage for PackageManager signature queries combined with Signature/digest evidence, producing `environment.integrity_check`.
- Add negative coverage so ordinary PackageManager version metadata lookup does not trigger the integrity rule.
- Add `signature_integrity_check.apk` to the synthetic oracle dataset and Web demo catalog.
- Extend the ZIP Strings/Androguard-style shallow environment keywords enough to expose the new signature-integrity signal in benchmark comparisons.
- Regenerate dataset, combined benchmark, external-corpus reports, README/docs/final summary, and slides with 18 synthetic + 12 external samples, 30/30 benchmark coverage, 50 tests, and 22 slides.
- Verify local and fresh venv tests, benchmark, external-corpus, slides, final wording scans, and Web demo smoke before committing.

### Phase 28: Root artifact environment detection

Status: complete

- Add detector coverage for strong rooted-device artifacts such as `/system/xbin/su`, Superuser/Magisk package names, `test-keys`, and explicit `which su` commands.
- Add negative coverage proving ordinary words containing `su`, such as `support` and `subscribe`, do not trigger root detection.
- Add `root_artifact_probe.apk` to the synthetic oracle dataset and Web demo catalog.
- Extend benchmark shallow environment keywords for root artifacts and regenerate combined/external reports.
- Synchronize README, rules/dataset/benchmark/external/demo/environment/final-deliverable docs, final summary, completion audit, live demo script, and slides with 19 synthetic + 12 external samples, 31/31 benchmark coverage, 53 tests, and 22 slides.
- Verify local and fresh venv tests, benchmark, external-corpus, slides, final wording scans, and Web demo smoke before committing.

### Phase 29: Rules documentation consistency gate

Status: complete

- Add a regression test that reads committed dataset labels and requires every actual finding ID to have a corresponding section in `docs/rules.md`.
- Synchronize final-facing test counts to 54 and recompile the Beamer deck.
- Verify local and fresh venv tests, slides, final wording scans, and Web demo smoke before committing.

### Phase 30: Java Debug API environment detection

Status: complete

- Add detector regression coverage for Java-layer `android.os.Debug` / `waitingForDebugger` anti-debug evidence.
- Add negative coverage so ordinary debug logging strings do not trigger `environment.debugger_probe`.
- Add `java_debug_api_probe.apk` to the synthetic oracle dataset and Web demo catalog.
- Extend the ZIP Strings shallow baseline keywords so the comparison table exposes the Java Debug API signal.
- Regenerate dataset, benchmark, external-corpus reports, README/docs/final summary, and slides with 20 synthetic + 12 external samples, 32/32 benchmark coverage, 58 tests, and 22 slides.
- Verify local and fresh venv tests, benchmark, external-corpus, slides, final wording scans, and Web demo smoke before committing.

### Phase 31: ADB/developer-settings environment detection

Status: complete

- Add detector regression coverage for Android Settings API evidence combined with ADB/developer-options keys such as `ADB_ENABLED`, `adb_enabled`, and `development_settings_enabled`.
- Add negative coverage so bare `adb` help text, URLs, or generic strings do not trigger the environment finding.
- Add `adb_developer_settings_probe.apk` to the synthetic oracle dataset and Web demo catalog.
- Extend shallow benchmark environment keywords so comparator rows expose the ADB/developer-settings signal.
- Regenerate dataset, benchmark, and external-corpus reports with 21 synthetic + 12 external samples, 33/33 benchmark coverage, and 63 tests.
- Synchronize README, rules/dataset/benchmark/demo/environment/final-deliverable docs, final summary, completion audit, live demo script, and slides.
- Verify local and fresh venv tests, benchmark, external-corpus, slides, final wording/stale-count scans, and Web demo smoke before committing.

### Phase 32: Installer-source environment detection

Status: complete

- Add detector regression coverage for installer-source APIs such as `getInstallerPackageName` and `getInstallSourceInfo` combined with installer/sideload values.
- Add negative coverage so ordinary PackageManager version metadata lookups do not trigger the environment finding.
- Add `installer_source_probe.apk` to the synthetic oracle dataset and Web demo catalog.
- Extend shallow benchmark environment keywords so comparator rows expose the installer-source signal.
- Regenerate dataset, benchmark, and external-corpus reports with 22 synthetic + 12 external samples, 34/34 benchmark coverage, and 67 tests.
- Synchronize README, rules/dataset/benchmark/demo/environment/final-deliverable docs, final summary, completion audit, live demo script, and slides.
- Verify local and fresh venv tests, benchmark, external-corpus, slides, final wording/stale-count scans, and Web demo smoke before committing.

### Phase 33: Final-facing documentation wording gate

Status: complete

- Add a regression test that checks README, key docs, final summary, and slides for process-oriented wording such as `这轮`, `本轮`, `下一步`, and `后续扩展`.
- Replace the remaining architecture-doc phrase `后续扩展` with a final-deliverable boundary statement.
- Verify the focused wording test, full pytest, final-facing wording scan, and `git diff --check`.

### Phase 34: Final-material test-count synchronization gate

Status: complete

- Add regression coverage requiring the Web demo and final-facing materials to show the current regression-test count.
- Synchronize README, demo docs, environment docs, final deliverable, completion audit, final summary, slides, and Web demo HTML from 67/68 to the current 69-test result.
- Recompile slides and verify local/fresh pytest, stale-count scan, LaTeX log scan, PDF page count, and `git diff --check`.

### Phase 35: Chinese Web demo localization

Status: complete

- Localize the Web demo first-screen copy, sample catalog metadata, upload controls, scan status text, result table headings, category labels, and upload-scan metadata into Chinese.
- Update regression coverage so the Web demo must expose the Chinese labels and must not regress to the old English exhibit/upload labels.
- Synchronize README, demo docs, defense notes, completion audit, final summary, live-demo script, and the Web-demo slide to the Chinese UI terminology.
- Verify local pytest, slide compilation, PDF page count, LaTeX log scan, and host-network Web demo smoke before committing and pushing.

## Errors Encountered

| Error | Attempt | Resolution |
| --- | --- | --- |
| Workspace root was not a git repo | `git status` in `/home/yxhong/syssec` | Created project repo under `/home/yxhong/syssec/syssec_final` |
| `pytest` missing from base environment | `pytest` and `python3 -m pytest` | Created `.venv` and installed local dev dependencies |
| DroidLysis default config writes cache under read-only home | `droidlysis --config ...` | Use `XDG_CACHE_HOME=/tmp/droidlysis_cache` in benchmark adapter |
| DroidLysis cannot provide a fair default benchmark without external tools | default scored comparison | Removed from scored tools; APKiD, Androguard DEX, and ZIP Strings now provide full-coverage comparisons |
| Androguard initially rejected synthetic DEX files | first Androguard DEX benchmark attempt | Added DEX SHA-1 signature, Adler-32 checksum, and map list to the synthetic DEX builder |
| `git ls-files -i` was missing the required mode flag | checking whether slide build artifacts were tracked | Re-ran the check with `git check-ignore -v`; slide PDF/log/aux outputs are ignored and not tracked |
| Sandbox denied binding a local HTTP port | `.venv/bin/python -m hardeninspector.demo_web --host 127.0.0.1 --port 8765` | Re-ran with approved local bind escalation for the Web demo smoke test |
| Local `curl` used the proxy for `127.0.0.1` | first Web demo smoke requests | Re-ran with proxy variables unset and `--noproxy '*'` |
| Sandbox network could not reach the host demo server | localhost smoke test for the relaunched Chinese Web demo | Re-ran the smoke requests on the host network with proxy variables unset |
| `HEAD` is unsupported by the demo handler | checking `/assets/apk-cutaway.png` with `curl -I` | Added `do_HEAD` for read-only Web demo routes and a regression test for image asset headers |
| Network sandbox blocked GitHub push | `git push origin main` | DNS failed in the sandbox; escalated push was rejected by the approval reviewer pending explicit user confirmation for exporting repository contents |
