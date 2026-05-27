# Open-source Comparator Benchmark

Dataset: `hardeninspector_eval_v1`

## Overall Metrics

| Tool | Samples | Micro Precision | Micro Recall | Micro F1 | Macro F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| HardenInspector | 6/6 | 1.000 | 1.000 | 1.000 | 1.000 |
| APKiD | 6/6 | 1.000 | 0.400 | 0.571 | 0.450 |
| DroidLysis | 6/6 | 0.000 | 0.000 | 0.000 | 0.000 |

## Per-category F1

### HardenInspector

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscation | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| environment | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |

### APKiD

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| obfuscation | 0 | 0 | 3 | 0.000 | 0.000 | 0.000 |
| environment | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| native | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |

### DroidLysis

| Category | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| packer | 0 | 0 | 3 | 0.000 | 0.000 | 0.000 |
| obfuscation | 0 | 0 | 3 | 0.000 | 0.000 | 0.000 |
| environment | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |
| native | 0 | 0 | 2 | 0.000 | 0.000 | 0.000 |

## Comparator Scope Notes

- **HardenInspector**: Project detector following the midterm route: APK/AXML/DEX/native static parsing, feature extraction, explainable evidence-chain rules.
- **APKiD**: Open-source Android packer/protector/obfuscator identifier used as the main runnable baseline. Categories are mapped from APKiD's JSON match groups.
- **DroidLysis**: Open-source suspicious-sample pre-analysis tool. Included as an availability comparator; full output requires configured apktool/baksmali/dex2jar.
- **MobSF**: Open-source mobile security framework discussed qualitatively in docs; not executed in the offline benchmark because it requires a heavier service/docker workflow.
