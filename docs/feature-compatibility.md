# Tri-state dataset feature compatibility audit

`godeep.evaluation.compatibility` compares dataset feature order and category
metadata with a hash-verified saved backend result. It produces observations and
gaps, not classifier inputs or predictions. This is an offline research CLI;
production API/adapters and trained candidate artifacts are unchanged. No new
dependencies or database migrations.

```powershell
.\.venv\Scripts\python.exe -m godeep.evaluation.compatibility `
  --csv C:\Users\saura\Downloads\malgenome215dataset1260malware2539benign.csv `
  --categories C:\Users\saura\Downloads\datasetfeaturescategories.csv `
  --result C:\private-research\saved-result.json `
  --result-sha256 YOUR_64_CHARACTER_LOWERCASE_RESULT_DIGEST `
  --output C:\private-research\compatibility-v1.json
```

The result file must be the raw `data` object from the job result API, not its
response wrapper. Compare the exact saved-byte digest with retained provenance.
Reformatting JSON changes it. The tool verifies against the supplied digest;
it does not authenticate operator-supplied files or re-read original APK bytes.
Accepted result adapters/versions: static_review 1.0.1, threat_review 1.0.0,
risk_review 1.0.0 and evasion_review 1.0.0, schema 1. A valid input SHA-256 is
required. Unknown versions and mismatched hashes fail rather than being guessed.

The source CSV uses the existing strict binary B/S importer. Category metadata
must be headerless unique feature/category pairs, at most 1 MiB/2,000 rows,
including `class,B=Benign; S=Malware`. Missing names and unused mappings are
reported exactly; aliases are never silently normalized. Source CSV, category,
result and feature-order hashes are recorded. Result files are capped at 10 MiB.
Output is exclusive; existing files are preserved. Exit code 2 reports invalid
inputs or unavailable output paths without echoing sensitive parser contents.

## Observation semantics

Features categorized exactly `Manifest Permission`, with uppercase permission
short names, are candidate mappings to `android.permission.<NAME>`. A completely
parsed manifest can establish declaration presence (value 1) or absence from
that inspected manifest (value 0). It does not establish grant, SDK applicability,
runtime access or abuse. Matching preserves all permission elements, selectors,
manifest SHA-256, max-SDK values and raw permission flags. Custom namespaces do
not match Android platform permissions by suffix.

Failed, missing or anomalous manifest coverage leaves permission observations
null/unknown. Inconsistent records claiming parsed coverage are rejected. API,
intent, command and unmapped features remain null/unknown even when related
triage rules exist: matching names alone would not establish the original
feature extraction semantics. Unknown values must not become zeros.

Every report sets `prediction_allowed=false`, `model_input=null` and
`compatibility_status=blocked_unverified_extraction_semantics`, even if all
requested candidate observations are known. These are research report fields;
no production inference path is added. Original dataset extraction equivalence
needs independent confirmation on controlled original APKs.

## Controlled fixture run, 21 October 2026

A synthetic APK containing our original binary-manifest and DEX fixtures was
processed by static_review and compared against the supplied 215-feature CSV
and category metadata. No user APK or malware sample was executed.

| Observation state | Count |
|---|---:|
| Declared permission candidates | 2 |
| Not declared in fixture manifest | 107 |
| Unknown / unsupported | 106 |
| Total | 215 |

There are **109 candidate permission mappings**, not 109 proven equivalent model
features. The two fixture declarations are READ_SMS and INTERNET. The other 106
features cannot yet be supplied by this conservative bridge. Seven dataset
features are unmapped by exact category name: `.system.bin`, `.system.app`,
`INJECT_EVENTS`, `BROADCAST_PACKAGE_REMOVED`,
`android.intent.action.CAMERA_BUTTON`, `android.intent.action.REBOOT` and
`READ_INPUT_STATE`.

These counts measure candidate feature alignment on a fixture, not detector
accuracy, current-app compatibility or model readiness. Original APK hashes,
feature extraction code and family/time metadata remain absent from the supplied
CSV. The next integration decision is to verify source extraction definitions
or collect a new corpus using our versioned extractor. Do not fill the 106
unknown entries to make the research model accept an APK.
