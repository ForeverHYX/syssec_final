# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 11/11 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 11/11 | 1.000 | 0.312 | 0.476 | 0.414 |
| Androguard DEX | 11/11 | 1.000 | 0.625 | 0.769 | 0.688 |
| ZIP Strings | 11/11 | 1.000 | 0.875 | 0.933 | 0.938 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| environment | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 1 | 1.000 | 0.750 | 0.857 |
| obfuscation | 0 | 0 | 5 | 0.000 | 0.000 | 0.000 |
| environment | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| native | 0 | 0 | 4 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 3 | 0 | 2 | 1.000 | 0.600 | 0.750 |
| environment | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 0 | 0 | 4 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 3 | 0 | 2 | 1.000 | 0.600 | 0.750 |
| environment | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
