# Research-only binary feature classification baseline

The CLI `python -m godeep.evaluation.classifier` imports the supplied binary
feature CSV, validates it, groups identical vectors, makes reproducible splits,
fits Bernoulli Naive Bayes on training groups and compares a training-majority
baseline. No APK is parsed/executed, data uploaded, production verdict generated,
or existing priority-policy weight changed. No new dependency or migration.

## Reproduce

From the repository terminal, choose a new output directory whose parent exists:

```powershell
.\.venv\Scripts\python.exe -m godeep.evaluation.classifier `
  --csv C:\Users\saura\Downloads\malgenome215dataset1260malware2539benign.csv `
  --output-dir C:\private-research\malgenome-baseline-v1
```

The importer requires UTF-8 CSV, unique nonblank headers, a final `class` column,
features exactly `0` or `1` and labels exactly `B` or `S`. B maps to benign/0,
S to malware/1 using the supplied category file's explicit legend. Bounds are
16 MiB, 100,000 data rows and 1,000 features. No automatic coercion, imputation,
category renaming or feature selection occurs. Conflicting labels for identical
vectors fail import. Other dataset schemas need separate explicit adapters.

Each identical vector group receives one weight in both fitting and evaluation.
Its source-row multiplicity remains in the split manifest. Vector identities are
SHA-256 of binary values in recorded feature order, not original APK hashes.
For each class, groups are sorted by a hash of seed plus vector identity. The
first floor(10%) go to test, the next floor(10%) to validation, the remainder to
training. Both classes need at least ten unique vectors. Default seed is
`godeep-malgenome-v1`. Row order cannot change group assignments. Family and time
leakage remain unresolved without original sample metadata.

The model uses Laplace smoothing alpha=1, training class priors, all original
features and a fixed 0.5 decision threshold. Both feature presence and absence
contribute through log likelihoods. No validation/test data fit parameters,
feature selection, calibration or thresholds. Validation is reported separately;
the first test result is retained without test-driven selection. Scores are
uncalibrated model outputs and must not be described as malware probabilities.

A new output directory contains `report.json`, `model.json`, `assignments.json`
and `predictions.json`. Existing directories are refused. Output failures can leave
a partial new directory; use a different new path after addressing the error.
Artifacts contain source hash, feature order, model parameters, split identities
and held-out predictions. Keep them private and outside Git. No pickle is used.
The experiment is deliberately separate from runtime adapters and API inference.

## First supplied-corpus run, 21 October 2026

Source SHA-256:
`c4bb0662c6dca005284de072fa966ba0945bbfba9ee9ee1eeb49dbf552d17242`.
3,799 source rows, 215 features, 2,463 unique vectors, 1,336 duplicate excess rows.

| Split | Unique vectors | Benign | Malware |
|---|---:|---:|---:|
| Train | 1,971 | 1,601 | 370 |
| Validation | 246 | 200 | 46 |
| Test | 246 | 200 | 46 |

| Metric | Validation | Test |
|---|---:|---:|
| Accuracy | 86.59% | 85.77% |
| Malware precision | 58.67% | 56.79% |
| Malware recall | 95.65% | 100.00% |
| F1 | 72.73% | 72.44% |
| False-positive rate | 15.50% | 17.50% |
| TP / FP / TN / FN | 44 / 31 / 169 / 2 | 46 / 35 / 165 / 0 |

The majority baseline is 81.30% accurate on each held-out split but detects zero
malware vectors. Accuracy alone is therefore insufficient. The Naive Bayes false
positive rate and precision require improvement. These are small, unique-vector
corpus results, not proof of modern APK performance or family independence.
No uncertainty intervals or external validation have been computed.

## Provenance and integration limits

The user supplied these source links:

- https://www.kaggle.com/datasets/saurabhshahane/android-malware-dataset
- https://www.kaggle.com/datasets/sha0401/android-malware-dataset

The pages were reachable, but dataset descriptions/licence details could not be
retrieved by the browsing tool. Exact file-to-page correspondence, original
collection provenance and licence remain unverified. No dataset or trained model
is added to Git. The ZIP supplied earlier contains duplicate copies of the two
CSVs rather than additional samples.

The category mapping has seven unmatched main-CSV feature names and does not
establish extraction semantics. Our production extractor does not reproduce all
215 features. Absent/unimplemented extraction must not be treated as a zero.
Before integration, document feature definitions and demonstrate parity on original
APKs or use a separately collected compatible dataset. Classifier labels remain
separate from analyst-priority labels, forensic observations and runtime evidence.
Next compare additional models using training/validation data, lock a policy, and
reserve a fresh external test set before making improved generalization claims.
