# HardenInspector Design

## Purpose

HardenInspector is the final exhibit for the `syssec_final` repository. It implements the detector direction from the course Android anti-hardening track: given an APK, it identifies evidence of code obfuscation, runtime packing, and environment-aware anti-analysis behavior.

## Scope

The MVP is a static-first command-line detector. It does not claim to prove maliciousness. It outputs a technical hardening profile and the evidence chain that caused each finding.

In scope:

- APK ZIP inventory and file entropy analysis.
- Android binary XML string-pool extraction for manifest evidence.
- DEX strings, type descriptors, method names, method references, and opcode statistics.
- Native library inventory and printable-string scanning.
- Explainable rule findings for packing, code obfuscation, reflection/dynamic loading, debugger/sandbox checks, Frida/Xposed checks, and suspicious encrypted payloads.
- JSON report and readable terminal summary.
- Reproducible test fixtures and unit tests.

Out of scope for the MVP:

- Full Android resource decoding.
- Full control-flow graph reconstruction.
- Commercial packer signature completeness.
- Dynamic Frida verification as a required dependency.
- Malware/benign classification.

## Architecture

The implementation is split into small Python modules:

- `apk.py`: read APK ZIP entries, manifest bytes, DEX files, native libraries, and resource metadata.
- `axml.py`: extract strings from Android binary XML string pools.
- `dex.py`: parse enough DEX structure to expose strings, descriptors, method IDs, code items, and opcode counts.
- `features.py`: convert raw parsed artifacts into normalized detector features.
- `rules.py`: evaluate explainable rules and produce findings with evidence.
- `report.py`: build stable JSON/text output.
- `cli.py`: command-line entrypoint.

## Detection Model

Each rule produces a finding with:

- `id`: stable rule identifier;
- `category`: `packer`, `obfuscation`, `environment`, or `native`;
- `severity`: `info`, `low`, `medium`, or `high`;
- `confidence`: `low`, `medium`, or `high`;
- `title` and `description`;
- `evidence`: concrete strings, file paths, method names, or statistics.

The detector prefers partial but inspectable evidence over opaque labels. When signals are suggestive but not definitive, confidence remains `low` or `medium`.

## Testing

Tests generate synthetic APK ZIPs and minimal DEX files in memory. They verify:

- APK inventory and entropy calculation;
- DEX parser extraction of strings, descriptors, method names, and opcode references;
- environment/packer/obfuscation rule hits with evidence;
- CLI JSON output shape.

## Delivery

The repo should contain source, tests, documentation, example commands, and milestone commits pushed to the GitHub repository named `syssec_final`.

