# Read-only research corpus audit

```powershell
python -m godeep.evaluation.corpus_audit --dataset DATA.csv --compare OTHER.csv --output NEW_AUDIT.json
python -m godeep.evaluation.corpus_audit --dataset archive.zip --member DATA.csv --output NEW_AUDIT.json
```

The audit bounds inputs and reads ZIP members without extraction. It expects
binary feature columns and a final B/S class column. It reports invalid rows,
duplicate vectors and contradictory labels. Cross-dataset overlap is computed
only when feature name sets match exactly; matching columns are reordered before
comparison. Similar names are not silently treated as aliases.

The audit does not repair values, resolve labels, train a classifier, or promote
a model. Retain reports privately because feature fingerprints may identify
samples. Original APKs, provenance, extractor specifications, independent test
splits and calibration remain required before production model promotion.
