# External APK Corpus v1

This directory contains public, ready-made APKs added to broaden the evaluation
range beyond the synthetic oracle dataset.

The corpus currently includes:

- 10 small APKs from DroidBench, selected from Reflection, DynamicLoading,
  EmulatorDetection, SelfModification, and Native categories.
- 1 real open-source APK from F-Droid: `org.billthefarmer.editor_198.apk`.
- 1 intentionally vulnerable Android test APK: PIVAA.

These APKs do not provide ground-truth labels for HardenInspector's hardening
categories. They are therefore used for scan coverage, finding distribution,
and comparator-output statistics, not for precision/recall scoring.

Run:

```bash
make external-corpus
```

Outputs are written to `reports/external_corpus/`.
