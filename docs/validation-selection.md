# Validation-only model comparison and threshold selection

The `godeep.evaluation.selection` CLI compares Bernoulli Naive Bayes against a
single-feature decision stump on the existing training/validation split. It does
not score test samples, replace the original baseline report, change production
adapters or modify the analyst-priority policy. No packages or migrations added.

```powershell
.\.venv\Scripts\python.exe -m godeep.evaluation.selection `
  --csv C:\Users\saura\Downloads\malgenome215dataset1260malware2539benign.csv `
  --output-dir C:\private-research\malgenome-selection-v1
```

The output parent must exist and output directory must be new. It writes
`report.json`, `candidate.json` and `assignments.json`. A null candidate means no
model met the research objective; there is no majority-model fallback. Failed
writes may leave partial new directories. Keep all data/model artifacts outside Git.

## Fixed selection procedure

The importer, duplicate-vector grouping, seed and stratified split are unchanged
from the first baseline. Training fits model parameters. Validation evaluates a
predeclared grid: 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 0.9999 and 0.999999.
These are uncalibrated model-score cutoffs, not confidence percentages.

Naive Bayes uses alpha=1 and training priors. The decision stump selects one
nonconstant binary feature by minimum training-weighted Gini impurity, breaking
ties by feature index. Its two leaves use Laplace-smoothed malware label fractions.
If no training feature varies, only Naive Bayes is compared. No validation
observation selects the stump feature or fits either model's parameters.

Research eligibility requires validation false-positive rate at most 5% and
malware recall at least 50%. Eligible candidates are ranked by highest recall,
then highest F1, then lowest false-positive rate, then algorithm name and cutoff.
These are experimental objectives, not validated operational acceptance criteria.
No eligible candidate means no selection. The report retains every candidate,
threshold, validation confusion matrix and a training-majority comparison.

The test split is assigned and its vector hashes/multiplicities retained for
provenance, but test feature values and labels are never used for scoring or
selection in this module. Split stratification itself uses supplied labels.
The original test set was inspected during baseline development, so a fresh
external evaluation is required before generalization claims. Do not select an
algorithm/seed after inspecting future external test outcomes.

## First local run, 21 October 2026

Source SHA-256:
`c4bb0662c6dca005284de072fa966ba0945bbfba9ee9ee1eeb49dbf552d17242`.
Seed `godeep-malgenome-v1`; same 1,971 training, 246 validation and 246 test unique
vectors as the baseline. Validation contains 200 benign and 46 malware-labelled
vectors. Selected candidate: Bernoulli Naive Bayes, threshold 0.9999.

| Validation metric | Initial threshold 0.5 | Selected threshold 0.9999 |
|---|---:|---:|
| True positives | 44 | 40 |
| False positives | 31 | 4 |
| True negatives | 169 | 196 |
| False negatives | 2 | 6 |
| Precision | 58.67% | 90.91% |
| Recall | 95.65% | 86.96% |
| False-positive rate | 15.50% | 2.00% |
| F1 | 72.73% | 88.89% |
| Accuracy | 86.59% | 95.93% |

A stricter cutoff reduces false alarms but misses more malware-labelled vectors.
These validation figures selected the candidate and are optimistically biased.
No new test metric is reported. This does not supersede the baseline test result
or establish a 95.93% accurate APK security platform.

## Remaining work

Vector groups cannot rule out family/temporal overlap. Supplied labels and licence
provenance remain operator-provided/unverified. The 215-feature schema is still
incompatible with full production extraction; absent extraction must not be zeroed.
The candidate stores feature order, source hash, seed, threshold and parameters
in JSON, marked `validation_candidate_only` and `not_calibrated`. No pickle,
production inference endpoint or automatic promotion is introduced.

Next establish feature extraction parity or collect a compatible corpus, then
independently evaluate a locked candidate on a new external dataset. Report
confusion counts, false positives, recall, confidence intervals and coverage before
production integration. Dynamic behaviour and forensic findings remain separate.
