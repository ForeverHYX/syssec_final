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
| Maintain GitHub repo named `syssec_final` | User objective | Local repo initialized, remote created/pushed, staged commits made |
| Commit and push at milestones | User objective | Git history shows staged commits and remote branch is up to date |

## Phases

### Phase 1: Repo and planning scaffold

Status: in_progress

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

Status: in_progress

- Run unit tests and CLI smoke tests.
- Verify git remote, commit history, and pushed branch.
- Audit every explicit user/course/report requirement before marking the goal complete.

## Errors Encountered

| Error | Attempt | Resolution |
| --- | --- | --- |
| Workspace root was not a git repo | `git status` in `/home/yxhong/syssec` | Created project repo under `/home/yxhong/syssec/syssec_final` |
| `pytest` missing from base environment | `pytest` and `python3 -m pytest` | Created `.venv` and installed local dev dependencies |

