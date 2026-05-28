# External APK Corpus v1

This directory contains public, ready-made APKs added to broaden the evaluation
range beyond the synthetic oracle dataset.

The corpus currently includes:

- 10 small APKs from DroidBench, selected from Reflection, DynamicLoading,
  EmulatorDetection, SelfModification, and Native categories.
- 1 real open-source APK from F-Droid: `org.billthefarmer.editor_198.apk`.
- 1 intentionally vulnerable Android test APK: PIVAA.

The manifest records coarse `expected_categories` and `label_basis` values so
these APKs are included in the 29-sample combined benchmark. They are still also
used for standalone scan coverage, finding distribution, and comparator-output
statistics.

Run:

```bash
make benchmark
make external-corpus
```

Benchmark outputs are written to `reports/benchmark/`; standalone external
statistics are written to `reports/external_corpus/`.
