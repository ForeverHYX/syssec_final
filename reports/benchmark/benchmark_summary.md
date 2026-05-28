# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1+external_apk_corpus_v1`

Scored external corpus: `external_apk_corpus_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 29/29 | 0.974 | 0.974 | 0.974 | 0.971 |
| APKiD | 29/29 | 1.000 | 0.211 | 0.348 | 0.272 |
| Androguard DEX | 29/29 | 0.800 | 0.421 | 0.552 | 0.478 |
| ZIP Strings | 29/29 | 0.862 | 0.658 | 0.746 | 0.745 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 8 | 0 | 1 | 1.000 | 0.889 | 0.941 |
| environment | 11 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 8 | 1 | 0 | 0.889 | 1.000 | 0.941 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 7 | 1.000 | 0.300 | 0.462 |
| obfuscation | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |
| environment | 5 | 0 | 6 | 1.000 | 0.455 | 0.625 |
| native | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 3 | 1.000 | 0.700 | 0.824 |
| obfuscation | 5 | 4 | 4 | 0.556 | 0.556 | 0.556 |
| environment | 4 | 0 | 7 | 1.000 | 0.364 | 0.533 |
| native | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 9 | 0 | 1 | 1.000 | 0.900 | 0.947 |
| obfuscation | 5 | 4 | 4 | 0.556 | 0.556 | 0.556 |
| environment | 6 | 0 | 5 | 1.000 | 0.545 | 0.706 |
| native | 5 | 0 | 3 | 1.000 | 0.625 | 0.769 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
