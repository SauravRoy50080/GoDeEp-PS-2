# Case-scoped analysis comparisons

POST `/api/v1/cases/{case_id}/comparisons` with a bearer session and:

```json
{"left_job_id": "UUID-OF-FIRST-RUN", "right_job_id": "UUID-OF-SECOND-RUN"}
```

Select two distinct completed `static_review` or `threat_review` jobs from the
same case, using the same adapter and adapter version. Runs can refer to different
APKs or repeated analyses of one APK. Selection is explicit; there is no implicit
latest run. Owners, analysts and viewers can read comparisons. Other users cannot
access case results.

The response groups permissions, exported/component settings, application flags,
certificate fingerprints, sensitive API findings, network candidates and local-feed
assertions into `left_only`, `right_only` and `changed` observations, with counts
and an unchanged count. Evidence references remain attached. Semantic keys exclude
sample-specific finding IDs, artifact hashes and XML indexes. Network normalization
uses the local-feed canonicalization rules; it does not expand domains to subdomains
or infer network activity from strings. Certificate observations are metadata and
do not establish APK signature validity.

Each side records job/sample IDs, input and result hashes, adapter/version,
completion time and extracted manifest identity. Stored source result bytes are
hash-verified on every comparison. Original APK bytes are not re-read: this compares
recorded analysis observations, not a new verification of original evidence.

Coverage is reported per category. Configuration, tool/component version, SDK or
feed differences, incomplete coverage, unresolved projection entries and output
truncation limit absence interpretation. Even compatible profiles establish only
absence in those selected observations. A left-only finding does not prove behaviour
was removed. Feed assertions can change independently of the APK. No risk-score
change, malware verdict, reachability or execution is inferred.

By default, each category retains up to 200 differences and the whole JSON response
is capped at 2 MiB. Configure `GODEEP_MAX_COMPARISON_ITEMS` and
`GODEEP_MAX_COMPARISON_BYTES` within their settings bounds. Counts describe all
projected differences even when retained lists are truncated. An oversized response
returns 413; unavailable, tampered or incompatible source runs return an error.

This endpoint is read-only, returns `Cache-Control: no-store`, and creates no job,
report snapshot or audit event. It requires no schema migration. Persisted forensic
reports remain a separate API. Comparisons are functional investigation aids;
benchmarking of detection accuracy remains pending.
