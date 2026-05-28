# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1+external_apk_corpus_v1`

Scored external corpus: `external_apk_corpus_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 31/31 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 31/31 | 1.000 | 0.200 | 0.333 | 0.254 |
| Androguard DEX | 31/31 | 0.783 | 0.450 | 0.571 | 0.499 |
| ZIP Strings | 31/31 | 0.818 | 0.675 | 0.740 | 0.729 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 8 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| environment | 13 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 7 | 1.000 | 0.300 | 0.462 |
| obfuscation | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |
| environment | 5 | 0 | 8 | 1.000 | 0.385 | 0.556 |
| native | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 3 | 1.000 | 0.700 | 0.824 |
| obfuscation | 4 | 5 | 4 | 0.444 | 0.500 | 0.471 |
| environment | 7 | 0 | 6 | 1.000 | 0.538 | 0.700 |
| native | 0 | 0 | 9 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 9 | 0 | 1 | 1.000 | 0.900 | 0.947 |
| obfuscation | 4 | 5 | 4 | 0.444 | 0.500 | 0.471 |
| environment | 9 | 1 | 4 | 0.900 | 0.692 | 0.783 |
| native | 5 | 0 | 4 | 1.000 | 0.556 | 0.714 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
