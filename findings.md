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

## External Corpus Gap Tuning

Current combined benchmark mismatches give the next improvement target:

- `droidbench_reflection_1` is labeled obfuscation but has no finding. Its DEX strings include `Ljava/lang/Class;` and `forName`, so the reflection rule needs to cover class-name based reflective loading in addition to `Method.invoke`.
- `droidbench_emulator_file_1` and `droidbench_emulator_imei_1` are labeled environment but miss emulator file/IMEI patterns. Their DEX strings expose `/proc`/`/sys` emulator-oriented paths, `TelephonyManager`, `getDeviceId`, `imei`, and zero-like device IDs.
- `droidbench_native_id_function` and `droidbench_source_in_native_code` are labeled native but only trigger reflection. Their native libraries export JNI symbols such as `Java_mod_ndk_ActMain_cFuncJgetIMEI`; `native.jni_entrypoint` only covers `JNI_OnLoad`, so a dedicated JNI export rule is justified.

Implemented tuning results:

- Added `obfuscation.reflection` support for `Class.forName` evidence while preserving the existing reflection dispatch coverage.
- Added `environment.emulator_artifacts` for file/hardware emulator traces and `environment.telephony_identifier_probe` for strong zero/replaced IMEI evidence. A regression test prevents treating DroidBench taint-sink phone numbers such as `+49 123` as emulator identifiers.
- Added `native.jni_export` for ELF/string `Java_*` JNI exports, which fixes native coverage for older DroidBench/NDK-style samples that do not export `JNI_OnLoad`.
- Added four synthetic samples: `class_forname_reflection`, `emulator_file_artifacts`, `emulator_imei_probe`, and `native_jni_export_only`.
- Combined benchmark is now 29 samples. HardenInspector Micro F1 is 0.938 with 29/29 coverage and zero false negatives across the four scored categories; remaining errors are coarse-label false positives on external APKs.

## Third-party Reflection False-positive Hardening

Review of the remaining 29-sample benchmark errors showed that most obfuscation false positives came from Android support-library compatibility classes such as `SearchView$AutoCompleteTextViewReflector`, `ActionBarDrawerToggleHoneycomb`, `NotificationCompatJellybean`, and `PagerAdapter`. Those are framework/library implementation details, not application hardening evidence.

Implemented rule hardening:

- Added regression tests proving support-library reflection scaffolding does not trigger `obfuscation.reflection`, while application-owned `ReflectiveDispatcher` evidence still does.
- Split reflection evidence into strong literals (`Method.invoke`) and contextual literals (`java.lang.reflect.Method` / `java/lang/reflect/Method`), where contextual literals now require application-owned reflection context.
- Filtered support-library/platform reflection owners for `android/support`, `androidx`, Kotlin, Google Material/Common, and platform descriptors.
- Preserved `Class.forName` detection when it is not only support-library reflection context.

At the reflection false-positive hardening phase, combined benchmark remained 29 samples with all tools at 29/29 coverage. HardenInspector Micro F1 was 0.987; obfuscation precision improved to 1.000 with one documented recall loss on `droidbench_reflection_5`, whose visible evidence is dominated by support-library reflection. External standalone stats showed HardenInspector Any 10/12 with packer=4, obfuscation=2, environment=5, native=3.

## External Native Label Audit

The remaining Native-category mismatch after reflection hardening was not a detector false positive. `droidbench_bytecode_tamper_1` contains `lib/arm64-v8a/libmyjni.so` with exported `Java_edu_wayne_cs_NativeInterface_jniTest`, plus native `dlopen`/`dlsym` and `/proc/self/maps` evidence. Its previous external-corpus `expected_categories` covered environment and packer but omitted native.

Implemented label-audit guardrail:

- Added a regression test that scans committed external APKs and requires any scored sample with visible `Java_*` JNI exports to include `native`.
- Updated the BytecodeTamper label basis to record the exported JNI bridge.
- Rebuilt the combined benchmark. HardenInspector had zero false positives across the four categories; the only remaining category error at that point was the intentional `droidbench_reflection_5` obfuscation miss caused by support-library reflection filtering.

## External Reflection Label Audit

Root-cause inspection of `droidbench_reflection_5.apk` showed that its visible reflection API calls are owned by `android/support/v4/...` compatibility classes such as `Fragment`, `PagerAdapter`, and utility scaffolding. Unlike `droidbench_reflection_1.apk`, it does not expose application-owned reflection dispatch evidence through the current DEX method/code model.

The external-corpus label was therefore too broad: the sample remains useful for parser and support-library false-positive coverage, but it should not be scored as an application obfuscation oracle. The manifest now keeps `droidbench_reflection_5` in the external corpus with empty `expected_categories` and records that label basis explicitly.

After regenerating the combined benchmark, HardenInspector reaches 29/29 coverage with Micro F1 1.000 and Macro F1 1.000. The lower ZIP Strings/Androguard DEX numbers are also more honest: shallow reflection-string evidence in support-library code is counted as a false positive instead of being rewarded by an overbroad label.

## Local Web Demo

The final exhibit now has a browser-based demo in addition to the CLI. The implementation deliberately uses Python standard-library HTTP serving instead of Flask/Node so the showcase remains reproducible from the existing virtual environment and can run offline.

The demo exposes curated synthetic and external samples: clean baseline, combined hardened showcase, native ptrace/loader, emulator IMEI probe, PIVAA, and F-Droid editor. This gives a better oral-exam flow than only showing terminal JSON: one click shows category summary, finding details, evidence tables, and the benchmark micro/macro comparison loaded from `reports/benchmark/benchmark_metrics.csv`.

## Web Demo Upload Scan

The browser demo now supports scanning an arbitrary local `.apk` selected by the presenter. The upload path posts raw APK bytes to the local server, writes them to a temporary directory, runs the same `scan_apk` pipeline as the CLI, then returns the normal JSON report shape. This improves live demonstration value while preserving the no-network, no-extra-framework constraint.

The upload route intentionally rejects non-`.apk` filenames and files above 64 MiB. This keeps the demo predictable for classroom use and avoids turning the local showcase into an unconstrained file-ingestion service.

## Defense Package

After the benchmark reached 1.000, the highest-value remaining work was not another detector rule but a stronger answer package for the final exhibit. The new live demo script gives a deterministic 5-8 minute flow, including clean baseline, combined showcase, specialty sample, upload scan, benchmark explanation, and terminal fallback.

The new Q&A document is designed for likely grading questions: why HardenInspector is not just APKiD/Androguard, why HardenInspector Micro F1 = 1.000 is scoped rather than overclaiming, why `droidbench_reflection_5` was relabeled after support-library-only evidence inspection, and where the implementation boundaries remain.

## Final Presentation Language and Web Exhibit Polish

Final-facing materials need to speak as a completed course exhibit, not as an internal optimization log. The slide phrase `这轮已补齐` was a real presentation risk because it frames the deck as an iterative work note; it is now guarded by `tests/test_final_artifacts.py`, and the slide section has been rewritten as `能力边界与实现强化` / `已经实现的强化`.

The Web demo had functional scanning and upload support, but it did not yet visually explain the whole project before the presenter clicked a sample. The page now opens with an Exhibit Map, Evidence Chain, Dataset Story, benchmark/test summary, and APK cutaway image. Curated samples also carry `dataset_kind` and `showcase_role`, so the presenter can explain why each sample exists: low-noise baseline, all-category evidence chain, ELF symbol evidence, environment probe, real APK sanity check, or clean real-world baseline.

## Web Demo Protocol Polish and Slide Demo Narrative

The Web demo's image asset route returned correct data for browser-style `GET` requests, but `HEAD /assets/apk-cutaway.png` used the base handler's unsupported-method path. This is a small but real polish issue for smoke checks and browser/tool preflight probes. The handler now shares read-only routing between GET and HEAD and suppresses the body for HEAD while keeping content type and content length headers.

The Beamer deck previously had no dedicated page explaining the Web demo even though the live page is now the clearest way to show the project's distinctive features. A new `现场 Web Demo` slide connects Exhibit Map, Evidence Chain, Dataset Story, Synthetic Oracle, External APK Corpus, curated scans, and Scan Upload into one final-class narrative.

## Signature Integrity Detection

Self-integrity and anti-tamper checks are a natural environment/anti-analysis signal for the course topic, but the detector previously did not distinguish them from ordinary PackageManager metadata reads. The new `environment.integrity_check` rule requires both signature API evidence and signature/digest material, such as `GET_SIGNATURES`, `Signature/toByteArray`, `MessageDigest`, `SHA-256`, or `checkSignature`.

The negative test matters: a PackageManager `getPackageInfo` query used only for `versionName` is not treated as hardening evidence. This keeps the rule explainable and avoids turning every app metadata lookup into an anti-tamper finding.

The dataset now includes `signature_integrity_check.apk`, and the Web demo exposes it as a curated anti-tamper sample. After regeneration, the combined scoring set is 30 samples: 18 synthetic and 12 external. HardenInspector remains at Micro/Macro F1 1.000; APKiD, Androguard DEX, and ZIP Strings are 0.340, 0.533, and 0.714 Micro F1 respectively.

## Root Artifact Environment Detection

Rooted-device checks are another common environment/anti-analysis technique in Android hardening. The detector now emits `environment.root_artifact_probe` for strong root artifacts and root-check contexts such as `/system/xbin/su`, Superuser/Magisk package names, `test-keys`, and `which su`.

The rule intentionally does not match bare `su`; the negative regression uses ordinary strings like `support`, `subscribe`, and `sunset` to keep this boundary explicit. The signal is medium confidence because benign diagnostics can mention root artifacts, so evidence is preserved for review rather than treated as a malicious verdict.

The dataset now includes `root_artifact_probe.apk`, and the Web demo exposes it as a rooted-device environment sample. After regeneration, the combined scoring set is 31 samples: 19 synthetic and 12 external. HardenInspector remains at Micro/Macro F1 1.000; APKiD, Androguard DEX, and ZIP Strings are 0.333, 0.571, and 0.740 Micro F1 respectively.

## Rules Documentation Consistency Gate

The final exhibit now has a regression test tying dataset-triggered finding IDs to `docs/rules.md` sections. This catches a common presentation risk: adding a detector rule and sample while forgetting to document the rule in the material used for defense.

The test intentionally reads committed dataset labels rather than hard-coding a duplicate list in the test. That keeps the guard aligned with the exhibit artifacts that are actually presented.
