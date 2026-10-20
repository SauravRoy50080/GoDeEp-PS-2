# Explainable static review prioritization

Queue adapter `risk_review` version 1.0.0 using the existing case-scoped job API:

```http
POST /api/v1/cases/{case_id}/analyses
Content-Type: application/json
Authorization: Bearer YOUR_SESSION
```

```json
{"sample_id": "SAMPLE-UUID", "adapter": "risk_review"}
```

The worker creates one verified static/threat-review snapshot. Results retain
manifest, DEX, resource and local-feed evidence and add `data.risk_review`.
No new dependencies or migration are needed. Restart the API and worker after
updating. Existing adapter versions and historical outputs are unchanged.

## Meaning and policy

The 0-100 score prioritizes analyst review. It is not a calibrated probability,
malware classification, severity certification or guarantee of security. Policy
version 1.0.0 is recorded in the result and component versions. Training is not
performed. The weights and thresholds below are operator-designed initial values.

| Rule | Full points |
|---|---:|
| Manifest debuggable | 10 |
| Manifest cleartext declared | 10 |
| Manifest backup declared | 5 |
| Manifest exported review | 5 |
| DEX dynamic loading | 10 |
| DEX debugger check | 5 |
| DEX reflection | 3 |
| DEX native loading | 3 |
| DEX process execution | 8 |
| DEX SMS send | 8 |
| DEX location access | 4 |
| DEX media recording | 4 |

Manifest rules require an existing evidence-bearing static finding. API rules get
full points for decoded invoke evidence, or integer quarter points (minimum one)
for method-identifier references. Neither establishes execution or reachability.
Unknown evidence states and unlisted rules add no points. Permission declarations,
network strings and unverified certificate metadata alone add none.

Each rule contributes at most once, taking the maximum evidence weight across
its findings. Repeated methods, selectors, evidence or duplicate finding IDs do
not accumulate points. Contributions are allocated in sorted rule-ID order with
category caps of manifest 25, API 35 and intelligence 40. Every contribution lists
requested and awarded points and source finding IDs; those IDs resolve to evidence
in the same result. Some valid contributions receive fewer or zero awarded points
when the category cap is reached. Category totals and awarded points reconcile
exactly to the score.

Intelligence uses the maximum retained active source assertion: suspicious 20 or
malicious 40, with benign-only claims adding zero. It requires an available pinned
feed and a matched indicator from the existing temporal-validity matcher. A benign
claim conflicting with a suspicious/malicious claim excludes that indicator from
scoring and records its index and reason. The conflict flag excludes it even when
retained matches are truncated. Other non-conflicting indicators can still
contribute. Match/provider counts do not sum. Feed hash, indicator references and
source record IDs are recorded. Claims remain source assertions, not verified truth.
No provider is contacted and APKs are not uploaded to external services.

Without a configured feed the adapter still runs static prioritization and reports
intelligence as unavailable. To enable it, use the existing private
`GODEEP_INTEL_FEED_PATH` and pinned `GODEEP_INTEL_FEED_SHA256` configuration described
in [offline intelligence](offline-threat-intelligence.md). Runtime feed configuration
is passed only to the trusted adapter subprocess; private paths are not in job config.

Priorities are `routine` below 20, `elevated` from 20 through 49 and `high` from 50.
Routine/zero is not safe or clean. These thresholds are not validated. Dynamic,
native-behaviour and calibration gaps are always present; manifest, DEX, resource,
correlation and intelligence gaps are added when incomplete. `assessment_complete`
is always false. Missing observations add no points but also cannot establish
absence: scores from incomplete/different profiles must not be interpreted as a
reduction in actual risk.

## Use and remaining validation

Existing case permissions, original/result hashing, bounded worker output and
forensic JSON reports apply. Select the risk-review job when creating a report to
retain the policy and explanations. The comparison endpoint currently supports
only static/threat review jobs and does not compare these priority scores.

This adapter reuses threat review and does not score the separate evasion adapter
again. Co-occurrence does not imply independent evidence. Additional evasion rules,
full payload analysis, Android runtime analysis and learned classifiers are pending.
Dataset evaluation should measure category precision/recall, false positives and
priority utility with family/deduplication and temporal splits before tuning these
weights. Keep a held-out evaluation set. No accuracy metric is established by unit
or integration test counts.
