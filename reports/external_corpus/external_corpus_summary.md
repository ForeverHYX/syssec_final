# External APK Corpus Scan Statistics

Corpus: `external_apk_corpus_v1`

External APKs have source metadata, checksums, and coarse expected_categories used by the combined benchmark. This standalone report remains coverage and finding-distribution statistics; precision/recall scores are reported in reports/benchmark/.

## Coverage and Category Counts

| Tool | Samples | Any category | Packer | Obfuscation | Environment | Native |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 12/12 | 9 | 4 | 6 | 3 | 0 |
| APKiD | 12/12 | 2 | 0 | 0 | 2 | 0 |
| Androguard DEX | 12/12 | 8 | 3 | 6 | 1 | 0 |
| ZIP Strings | 12/12 | 9 | 4 | 6 | 2 | 0 |

## HardenInspector Sample Results

| Sample | Source | Context | Categories | Findings |
| --- | --- | --- | --- | --- |
| droidbench_reflection_1 | DroidBench | Reflection | - | - |
| droidbench_reflection_5 | DroidBench | Reflection | obfuscation | obfuscation.reflection |
| droidbench_dynamic_both_1 | DroidBench | DynamicLoading | packer | packer.high_entropy_payload, packer.dynamic_code_loading |
| droidbench_dynamic_source_1 | DroidBench | DynamicLoading | packer | packer.high_entropy_payload, packer.dynamic_code_loading |
| droidbench_emulator_build_1 | DroidBench | EmulatorDetection | environment, obfuscation | obfuscation.reflection, environment.system_properties |
| droidbench_emulator_file_1 | DroidBench | EmulatorDetection | obfuscation | obfuscation.reflection |
| droidbench_emulator_imei_1 | DroidBench | EmulatorDetection | - | - |
| droidbench_bytecode_tamper_1 | DroidBench | SelfModification | environment, packer | environment.instrumentation_probe, packer.native_dynamic_loader |
| droidbench_native_id_function | DroidBench | Native | obfuscation | obfuscation.reflection |
| droidbench_source_in_native_code | DroidBench | Native | obfuscation | obfuscation.reflection |
| fdroid_editor | F-Droid | open-source real APK | - | - |
| pivaa | PIVAA | intentionally vulnerable Android test APK | environment, obfuscation, packer | packer.high_entropy_payload, packer.dynamic_code_loading, obfuscation.reflection, environment.instrumentation_probe |
