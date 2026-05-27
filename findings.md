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

Androguard is used as a runnable open-source DEX parser baseline. It does not replace HardenInspector's implementation; the benchmark adapter only asks Androguard to parse DEX strings/classes/methods and maps those shallow signals to the project categories. This proves the synthetic APKs are valid enough for an external Android parser and gives a fair 10/10-coverage comparator.

ZIP Strings is a dependency-free baseline added to make the benchmark range wider. It scans ZIP entry names and printable strings without Android structure awareness. It is intentionally simple, so the report can distinguish raw string visibility from HardenInspector's structured evidence-chain output.

The expanded default scored benchmark is therefore: HardenInspector, APKiD, Androguard DEX, and ZIP Strings. All four produce results for all 10 committed synthetic APKs. DroidLysis and MobSF remain documented qualitative references outside the metric table.

Important route constraint from user: open-source implementations are benchmarks only. HardenInspector must continue following the midterm report route: static parsing, feature extraction, explainable rules, and evidence-chain output. Do not copy APKiD/MobSF/DroidLysis rules into the detector.

## Slide Visual Findings

The ZJU Beamer deck uses generated imagery only for the complex APK cutaway illustration. The architecture, dataset matrix, and benchmark metrics are rendered with LaTeX/TikZ/tables so text remains readable and controlled. The generated image contains no required labels; it is a visual aid for understanding APK decomposition.
