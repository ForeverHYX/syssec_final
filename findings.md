# Findings

## Course Android Track

The referenced course page section `3.Android应用抗加固分析` states that the Android final project asks students to understand common code obfuscation, packing, and environment-detection techniques, then choose one of two final directions: reproduce an existing deobfuscation/unpacking/environment-countermeasure work, or implement a tool that detects which hardening techniques an Android app uses.

Our selected direction is the detector implementation.

## Midterm Report Requirements

The midterm PDF is titled `Android 应用抗加固分析：代码混淆、加壳与环境检测技术的检测框架设计`.

The report proposes HardenInspector as a lightweight, reproducible, static-first APK hardening detector. Its core MVP should:

- input an APK file;
- parse Manifest strings, DEX metadata, native libraries, and resource/file inventory;
- extract evidence for code obfuscation, runtime packing, and environment-aware detection;
- use explainable static rules rather than opaque ML;
- output a JSON report with matched rules, evidence locations, and risk explanations;
- support small reproducible evaluation with self-written or controllable APK fixtures;
- keep dynamic Frida hooks as optional extension work, not core delivery.

## Implementation Direction

To avoid dependency/network fragility in the core detector, the MVP uses Python standard-library parsing for APK ZIPs and enough DEX/AXML structure to support evidence extraction. Androguard is not part of the detector implementation route; it is used only as an optional benchmark comparator.

## Open-source Comparator Findings

APKiD is a direct comparator for part of HardenInspector's goal: its GitHub README describes it as an Android application identifier for packers, protectors, obfuscators, and oddities. It supports JSON output and scans APK/DEX inputs. In local tests on the committed synthetic dataset, APKiD 3.1.0 detected Jiagu on shell-like samples and `ro.kernel.qemu check` on environment-check samples.

DroidLysis is a broader pre-analysis tool for suspicious Android samples. Its PyPI documentation states that it disassembles Android samples, organizes output, and searches for suspicious code spots. It can process APK/DEX/ZIP/RAR/directories, but full local operation requires external tools such as Apktool, Baksmali, and optionally Dex2jar. In this repo, it is now treated as a qualitative reference only. It is intentionally removed from the scored default benchmark, because scoring a partially unavailable pipeline as zero would be an unfair comparison.

MobSF is a broad mobile security framework with static and dynamic analysis support for APK and other mobile binaries. It is relevant for qualitative comparison, but running a full MobSF service/docker pipeline is heavier than the committed offline benchmark. The benchmark will document it as a scope comparator and keep APKiD as the primary runnable baseline.

Androguard is used as a runnable open-source DEX parser baseline. It does not replace HardenInspector's implementation; the benchmark adapter only asks Androguard to parse DEX strings/classes/methods and maps those shallow signals to the project categories. This proves the synthetic APKs are valid enough for an external Android parser and gives a fair 11/11-coverage comparator.

ZIP Strings is a dependency-free baseline added to make the benchmark range wider. It scans ZIP entry names and printable strings without Android structure awareness. It is intentionally simple, so the report can distinguish raw string visibility from HardenInspector's structured evidence-chain output.

At the 11-sample synthetic-only benchmark phase, the expanded default scored benchmark was: HardenInspector, APKiD, Androguard DEX, and ZIP Strings. All four produced results for all 11 committed synthetic APKs. DroidLysis and MobSF remain documented qualitative references outside the metric table.

Important route constraint from user: open-source implementations are benchmarks only. HardenInspector must continue following the midterm report route: static parsing, feature extraction, explainable rules, and evidence-chain output. Do not copy APKiD/MobSF/DroidLysis rules into the detector.

## Slide Visual Findings

The ZJU Beamer deck uses generated imagery only for the complex APK cutaway illustration. The architecture, dataset matrix, and benchmark metrics are rendered with LaTeX/TikZ/tables so text remains readable and controlled. The generated image contains no required labels; it is a visual aid for understanding APK decomposition.

## Control-flow Limitation Optimization

The previous limitation around opcode/control-flow statistics has been partially optimized without attempting full CFG recovery. `dex.py` now exposes an opcode profile with instruction count, control-flow count, density, and if/goto/switch/throw counts. `rules.py` turns dense branch/jump patterns into `obfuscation.control_flow_density` findings with DEX-location evidence.

The dataset now includes `control_flow_flattening.apk`, a synthetic control-flow-density sample. At the 11-sample phase, scored benchmark coverage remained 11/11 for HardenInspector, APKiD, Androguard DEX, and ZIP Strings; Micro F1 values were 1.000, 0.476, 0.769, and 0.933 respectively. The slide deck explains this as a lightweight, reproducible pre-screening signal rather than a full CFG implementation.

Synthetic APK generation now fixes ZIP entry timestamps and permissions. Running `make dataset` twice keeps APK SHA-256 values stable, so the committed dataset is reproducible instead of changing due only to archive metadata.

## External APK Corpus Research

DroidBench is suitable as an external test-suite source because its README describes it as an open Android taint-analysis benchmark and states that the distribution contains source projects plus readily compiled APKs in the `apk` folder. It is not a hardening-specific oracle, so it should be used for external scan coverage and finding-distribution statistics, not for precision/recall against packer/obfuscation/environment/native labels.

F-Droid is suitable as an external benign/open-source APK source. F-Droid package pages expose direct APK downloads and state that listed builds are built and signed by F-Droid and correspond to source tarballs. These samples can broaden real-world APK parsing coverage, but they do not provide hardening ground truth; use them for scan statistics and false-positive review rather than scored oracle metrics.

PIVAA/InsecureShop-style intentionally vulnerable APKs are useful as security testing APKs, but their labels target vulnerability scanners, not hardening detection. If included, they should follow the same external-corpus treatment: committed source URL, checksum, scan result, and no precision/recall oracle unless a hardening label is explicitly justified.

Implementation decision: include 12 external APKs in `datasets/external_apk_corpus_v1/`: 10 DroidBench APKs, one F-Droid APK (`org.billthefarmer.editor_198.apk`), and PIVAA. The corpus is intentionally small enough to commit, about 5.7 MiB, while spanning reflection, dynamic loading, emulator detection, native, self-modification, a normal open-source app, and an intentionally vulnerable security-test APK.

External corpus statistics after rule tuning: all four tools cover 12/12 samples. HardenInspector reports at least one category on 9/12 samples with category counts packer=3, obfuscation=6, environment=3, native=0. APKiD reports 2/12, Androguard DEX reports 8/12, ZIP Strings reports 9/12. `fdroid_editor` has no HardenInspector finding after tightening `control_flow_density`, which reduces a real false-positive risk found by the external corpus.

## External Corpus Scoring Decision

The external APKs are now included in the default scored benchmark through coarse, auditable `expected_categories` mappings in `datasets/external_apk_corpus_v1/manifest.json`. These are not official hardening ground-truth labels from DroidBench/F-Droid/PIVAA; they are project-level mappings from the public sample scenario to HardenInspector categories, recorded with `label_basis` for review.

Current combined scoring set: 11 synthetic oracle APKs + 12 external APKs = 23 samples. Current Micro F1 values are HardenInspector 0.842, APKiD 0.389, Androguard DEX 0.653, and ZIP Strings 0.778. The separate `make external-corpus` report remains useful because it shows external coverage and finding distribution independent of the scoring labels.

## Native Structural Evidence Expansion

Review identified two high-value gaps for the next improvement pass:

- Native analysis currently treats `.so` files mostly as printable-string blobs. A lightweight ELF reader can extract `.dynsym` / `.dynstr` names and preserve symbol-level evidence locations without becoming a full disassembler.
- ZIP Strings remains close to HardenInspector on the benchmark because many synthetic samples expose obvious strings. Adding samples whose main evidence is entropy or parsed ELF symbols makes the benchmark better test structured analysis.

Chosen first slice: implement a small standard-library ELF symbol extractor, wire it into `features.py`, add rules for native anti-debug/dynamic-loader symbols, then add synthetic samples for encrypted-payload-only and native ptrace/dlopen evidence.

Implemented slice results:

- `src/hardeninspector/native.py` parses ELF32/ELF64 section headers and extracts `.dynsym` / `.symtab` symbols with table, binding, and type metadata.
- `environment.native_debugger_symbol` reports Native `ptrace`, `prctl`, and `syscall` symbols as environment evidence.
- `packer.native_dynamic_loader` reports Native `dlopen`, `android_dlopen_ext`, `dlsym`, and `dladdr` as runtime-loader evidence.
- `datasets/hardeninspector_eval_v1/` now contains 13 synthetic APKs, adding `high_entropy_payload_only` and `native_ptrace_loader`.
- Combined benchmark is now 25 samples. HardenInspector Micro F1 is 0.866; ZIP Strings is 0.794, so the gap widened modestly after adding a non-string entropy-only sample and symbol-aware native evidence.
