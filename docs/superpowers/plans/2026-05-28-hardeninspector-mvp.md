# HardenInspector MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tested Python CLI that scans APKs and reports explainable evidence for Android hardening techniques.

**Architecture:** Use Python standard-library parsers for APK ZIP structure, Android binary XML strings, and the subset of DEX needed for static evidence. Normalize parsed artifacts into features, evaluate deterministic rules, then emit JSON and readable summaries.

**Tech Stack:** Python 3.10+, `pytest`, standard library only at runtime.

---

### Task 1: Repository Skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `src/hardeninspector/__init__.py`
- Create: `tests/__init__.py`

- [x] **Step 1: Write the skeleton metadata**

Create packaging metadata with a console script named `hardeninspector`.

- [x] **Step 2: Commit**

Run:

```bash
git add .
git commit -m "docs: add hardeninspector project plan"
```

### Task 2: APK and Binary Helpers

**Files:**
- Create: `src/hardeninspector/apk.py`
- Create: `src/hardeninspector/axml.py`
- Create: `src/hardeninspector/util.py`
- Test: `tests/test_apk_axml.py`

- [ ] **Step 1: Write failing tests**

Tests should cover ZIP inventory, entropy values, printable-string extraction, and AXML string-pool extraction from a generated binary XML-like blob.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
pytest tests/test_apk_axml.py -q
```

Expected: FAIL because modules are missing.

- [ ] **Step 3: Implement helpers**

Implement `ApkArchive`, `FileEntry`, `shannon_entropy`, `extract_printable_strings`, and `extract_axml_strings`.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
pytest tests/test_apk_axml.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src tests
git commit -m "feat: parse apk inventory and axml strings"
```

### Task 3: DEX Parser

**Files:**
- Create: `src/hardeninspector/dex.py`
- Test: `tests/test_dex.py`
- Test helper: `tests/fixtures.py`

- [ ] **Step 1: Write failing tests**

Tests should build a minimal DEX with strings, type IDs, method IDs, class data, and invoke/const-string opcodes.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
pytest tests/test_dex.py -q
```

Expected: FAIL because parser is missing.

- [ ] **Step 3: Implement DEX parsing**

Implement `DexFile.parse`, string/type/method extraction, class data parsing, code item scanning, and opcode counting.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
pytest tests/test_dex.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src tests
git commit -m "feat: parse dex evidence for detector rules"
```

### Task 4: Features, Rules, Reports, CLI

**Files:**
- Create: `src/hardeninspector/features.py`
- Create: `src/hardeninspector/rules.py`
- Create: `src/hardeninspector/report.py`
- Create: `src/hardeninspector/cli.py`
- Test: `tests/test_detector.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Tests should generate APKs with known packer, obfuscation, reflection, dynamic loading, and environment strings.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
pytest tests/test_detector.py tests/test_cli.py -q
```

Expected: FAIL because detector modules are missing.

- [ ] **Step 3: Implement detector pipeline**

Implement feature extraction, rule evaluation, report serialization, and CLI scan command.

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
pytest tests/test_detector.py tests/test_cli.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add src tests README.md
git commit -m "feat: add hardening detector cli"
```

### Task 5: Documentation, Demo, and Final Verification

**Files:**
- Modify: `README.md`
- Create: `docs/demo.md`
- Optional copy: `docs/references/mid_term.pdf`

- [ ] **Step 1: Add demo docs**

Document installation, scan command, JSON output, interpretation, limitations, and course requirement mapping.

- [ ] **Step 2: Run full verification**

Run:

```bash
pytest -q
python -m hardeninspector --help
```

Expected: all tests pass and CLI help exits 0.

- [ ] **Step 3: Commit and push**

Run:

```bash
git add .
git commit -m "docs: add final exhibit guide"
git push -u origin main
```

