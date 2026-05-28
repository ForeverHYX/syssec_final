# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1+external_apk_corpus_v1`

Scored external corpus: `external_apk_corpus_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 23/23 | 0.857 | 0.828 | 0.842 | 0.848 |
| APKiD | 23/23 | 1.000 | 0.241 | 0.389 | 0.317 |
| Androguard DEX | 23/23 | 0.800 | 0.552 | 0.653 | 0.564 |
| ZIP Strings | 23/23 | 0.840 | 0.724 | 0.778 | 0.789 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 7 | 4 | 1 | 0.636 | 0.875 | 0.737 |
| environment | 6 | 0 | 2 | 1.000 | 0.750 | 0.857 |
| native | 4 | 0 | 2 | 1.000 | 0.667 | 0.800 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 4 | 1.000 | 0.429 | 0.600 |
| obfuscation | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |
| environment | 4 | 0 | 4 | 1.000 | 0.500 | 0.667 |
| native | 0 | 0 | 6 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 5 | 4 | 3 | 0.556 | 0.625 | 0.588 |
| environment | 4 | 0 | 4 | 1.000 | 0.500 | 0.667 |
| native | 0 | 0 | 6 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 5 | 4 | 3 | 0.556 | 0.625 | 0.588 |
| environment | 5 | 0 | 3 | 1.000 | 0.625 | 0.769 |
| native | 4 | 0 | 2 | 1.000 | 0.667 | 0.800 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
