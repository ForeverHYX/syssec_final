# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1+external_apk_corpus_v1`

Scored external corpus: `external_apk_corpus_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 30/30 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 30/30 | 1.000 | 0.205 | 0.340 | 0.262 |
| Androguard DEX | 30/30 | 0.762 | 0.410 | 0.533 | 0.471 |
| ZIP Strings | 30/30 | 0.806 | 0.641 | 0.714 | 0.708 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| environment | 12 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 7 | 1.000 | 0.300 | 0.462 |
| obfuscation | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |
| environment | 5 | 0 | 7 | 1.000 | 0.417 | 0.588 |
| native | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 3 | 1.000 | 0.700 | 0.824 |
| obfuscation | 4 | 5 | 4 | 0.444 | 0.500 | 0.471 |
| environment | 5 | 0 | 7 | 1.000 | 0.417 | 0.588 |
| native | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 9 | 0 | 1 | 1.000 | 0.900 | 0.947 |
| obfuscation | 4 | 5 | 4 | 0.444 | 0.500 | 0.471 |
| environment | 7 | 1 | 5 | 0.875 | 0.583 | 0.700 |
| native | 5 | 0 | 4 | 1.000 | 0.556 | 0.714 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
