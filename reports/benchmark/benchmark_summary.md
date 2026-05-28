# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1+external_apk_corpus_v1`

Scored external corpus: `external_apk_corpus_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 25/25 | 0.879 | 0.853 | 0.866 | 0.861 |
| APKiD | 25/25 | 1.000 | 0.206 | 0.341 | 0.269 |
| Androguard DEX | 25/25 | 0.800 | 0.471 | 0.593 | 0.507 |
| ZIP Strings | 25/25 | 0.862 | 0.735 | 0.794 | 0.792 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 7 | 4 | 1 | 0.636 | 0.875 | 0.737 |
| environment | 7 | 0 | 2 | 1.000 | 0.778 | 0.875 |
| native | 5 | 0 | 2 | 1.000 | 0.714 | 0.833 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 7 | 1.000 | 0.300 | 0.462 |
| obfuscation | 0 | 0 | 8 | 0.000 | 0.000 | 0.000 |
| environment | 4 | 0 | 5 | 1.000 | 0.444 | 0.615 |
| native | 0 | 0 | 7 | 0.000 | 0.000 | 0.000 |

### Androguard DEX

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 7 | 0 | 3 | 1.000 | 0.700 | 0.824 |
| obfuscation | 5 | 4 | 3 | 0.556 | 0.625 | 0.588 |
| environment | 4 | 0 | 5 | 1.000 | 0.444 | 0.615 |
| native | 0 | 0 | 7 | 0.000 | 0.000 | 0.000 |

### ZIP Strings

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 9 | 0 | 1 | 1.000 | 0.900 | 0.947 |
| obfuscation | 5 | 4 | 3 | 0.556 | 0.625 | 0.588 |
| environment | 6 | 0 | 3 | 1.000 | 0.667 | 0.800 |
| native | 5 | 0 | 2 | 1.000 | 0.714 | 0.833 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **Androguard DEX**: Open-source Androguard DEX parser baseline. It uses Androguard to extract DEX strings/classes/methods, then applies a shallow category mapping for comparison; APK manifest/native/resource evidence is intentionally out of scope.
- **ZIP Strings**: Dependency-free raw ZIP filename/string baseline. It shows what a shallow strings-only scanner can recover without structured Android parsing.
- **DroidLysis**: Removed from the scored benchmark because the local environment lacks its required apktool/baksmali/dex2jar pipeline; it remains a qualitative reference only.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
