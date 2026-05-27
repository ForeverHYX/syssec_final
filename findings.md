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

