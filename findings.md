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

To avoid dependency/network fragility, the MVP will use Python standard-library parsing for APK ZIPs and enough DEX/AXML structure to support evidence extraction. This keeps the final exhibit reproducible in the course environment while leaving Androguard integration as a future enhancement.

## Open-source Comparator Findings

APKiD is a direct comparator for part of HardenInspector's goal: its GitHub README describes it as an Android application identifier for packers, protectors, obfuscators, and oddities. It supports JSON output and scans APK/DEX inputs. In local tests on the committed synthetic dataset, APKiD 3.1.0 detected Jiagu on shell-like samples and `ro.kernel.qemu check` on environment-check samples.

DroidLysis is a broader pre-analysis tool for suspicious Android samples. Its PyPI documentation states that it disassembles Android samples, organizes output, and searches for suspicious code spots. It can process APK/DEX/ZIP/RAR/directories, but full local operation requires external tools such as Apktool, Baksmali, and optionally Dex2jar. In this repo, it is treated as an optional comparator with availability/status recorded rather than as the main benchmark baseline.

MobSF is a broad mobile security framework with static and dynamic analysis support for APK and other mobile binaries. It is relevant for qualitative comparison, but running a full MobSF service/docker pipeline is heavier than the committed offline benchmark. The benchmark will document it as a scope comparator and keep APKiD as the primary runnable baseline.

Important route constraint from user: open-source implementations are benchmarks only. HardenInspector must continue following the midterm report route: static parsing, feature extraction, explainable rules, and evidence-chain output. Do not copy APKiD/MobSF/DroidLysis rules into the detector.
