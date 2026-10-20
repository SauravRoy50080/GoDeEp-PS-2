# Offline analyst-priority evaluation foundation

The CLI validates labelled corpus splits and evaluates recorded `risk_review`
results. It does not run APKs, train models, tune thresholds or contact providers.
No dependencies, database migration or server endpoint are added.

## Input contract

Create a private UTF-8 JSON manifest outside Git. The example below intentionally
has no prediction; it demonstrates an abstention and is not a measured benchmark.
Replace the hash and provenance with actual reviewed records.

```json
{
  "schema_version": 1,
  "target": "analyst_review_priority",
  "dataset_id": "your-private-corpus-v1",
  "entries": [
    {
      "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "split": "test",
      "group_id": "application-lineage-1",
      "label": "review_required",
      "label_source": "Analyst review record identifier",
      "label_basis": "Independent documented reason requiring analyst review",
      "result_path": null,
      "result_sha256": null
    }
  ]
}
```

Labels are `review_required`, `routine` or `unknown`. These are analyst-priority
labels, not malware labels. A malicious/benign dataset needs a separately reviewed
mapping or a separate classification evaluator; the CLI rejects those labels
rather than silently reinterpreting them. Do not derive ground truth from the
same engine being evaluated. Source and basis are mandatory but their truth is
not independently verified by software.

Each APK SHA-256 occurs only once across the corpus. Groups represent related
application versions, duplicates or malware families; a group cannot span train,
validation and test splits. The operator must assign groups correctly. Hash-based
deduplication alone does not identify repackaging or family relationships.
Use validation for future tuning and keep test labels held out. Evaluation defaults
to test; it can evaluate another explicitly selected split without tuning anything.

When available, set both `result_path` and `result_sha256`. The path is relative to
an explicitly selected result directory. Save the raw analysis result JSON object
(the `data` field returned by the analysis result API, not the response wrapper).
Hash those exact saved bytes; reformatting JSON changes the digest. Compare this
digest with retained source provenance as part of dataset preparation. The tool
checks bytes against the manifest, not the authenticity of operator-supplied files.
A missing prediction is represented by null fields; a broken path, wrong digest
or malformed result fails the evaluation instead of silently being skipped.

Results must match schema 1, adapter `risk_review` 1.0.0 and the entry's input hash.
The evaluator recalculates policy 1.0.0 and requires the entire stored `risk_review`
object to match. Original APKs are not re-read or required. Paths and resolved
symlink targets must remain inside the result directory. Duplicate JSON keys and
non-finite JSON numbers are rejected. The corpus is capped at 4 MiB/10,000 entries;
each result is capped at 10 MiB and is read sequentially.

## Run from the repository terminal

```powershell
.\.venv\Scripts\python.exe -m godeep.evaluation `
  --manifest C:\private-corpus\manifest.json `
  --results-root C:\private-corpus\results `
  --split test `
  --output C:\private-corpus\evaluation-v1.json
```

Use an existing output parent directory and a new filename: reports are created
exclusively and an existing file is preserved. Exit code 2 indicates an invalid
input, unavailable path or output error. Sensitive exception contents are not
printed. Reports contain dataset and group IDs, label provenance, sample/result
hashes and per-entry scores; handle them as private investigation data.

## Report interpretation

The fixed positive threshold is 20 (the initial elevated-priority boundary).
TP/FP/TN/FN count only labelled entries with complete selected static coverage:
parsed manifest, decoded DEX calls, untruncated grouping and inspected selected
resources. Missing predictions or incomplete static phases abstain; unknown labels
are unlabelled and excluded from confusion metrics. Dynamic/native coverage and
policy calibration are still missing even for assessed entries.

The report contains precision, recall, F1 and false-positive rate on assessed
entries, with null for undefined denominators. Coverage of labelled entries,
positive abstentions and a conservative recall bound counting positive abstentions
as missed accompany these selective metrics. Review them together. A high selective
score on a small covered subset is not evidence of high overall accuracy.

Tool/component/feed profile fingerprints and per-row coverage gaps remain visible;
mixed profiles are flagged. They do not prove identical configuration limits,
acquisition conditions or threat-feed timing. Report metrics separately by a
controlled cohort when these differ; the current overall metrics pool selected
entries. Confidence intervals, family-weighted statistics, behavioural category
metrics, learned classifiers and automatic tuning remain future work.

No real corpus has been evaluated as part of implementation. Synthetic unit tests
validate arithmetic and workflow only. The next input needed is a description of
your dataset schema, labels, size and provenance so we can define the appropriate
review/classification/category targets before using APKs or training data.
