# Offline threat-intelligence correlation - milestone 10

## Run

The threat_review adapter combines the current static_review and resource_inventory
passes on one verified APK snapshot, then matches candidates against a pinned
operator-supplied local JSON feed. No network service is queried and APKs, hashes
or strings are not uploaded. No new Python dependency or database migration is added.
Signature verification remains a separate adapter and is not implied by this run.

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"threat_review"}
```

Submit through the existing authenticated case analyses endpoint, poll and retrieve
/result as described in [analysis jobs](analysis-jobs.md). The analyzer catalog
advertises this adapter as requiring operator configuration. With no feed configured,
static/resource analysis still completes and intelligence explicitly says not_checked.
No real-world threat feed is bundled or silently enabled. A training dataset is not
required; meaningful reputation matches require your trusted indicator source.

## Feed contract

The format is GoDeEp's local schema, not a native MISP or STIX import format.
Translate exported sources explicitly; automated provider connectors are future work.
This example uses synthetic data and illustrative dates, not real threat claims:

```json
{
  "schema_version": 1,
  "feed_id": "example-local-feed",
  "source_name": "Synthetic documentation example",
  "source_url": "https://example.org/",
  "published_at": "2026-10-20T00:00:00Z",
  "valid_until": "2026-10-21T00:00:00Z",
  "indicators": [
    {
      "id": "example-domain-1",
      "kind": "domain",
      "value": "example.org",
      "classification": "unknown",
      "confidence": "unknown",
      "observed_at": "2026-10-19T23:00:00Z",
      "valid_until": "2026-10-21T00:00:00Z"
    }
  ]
}
```

Use current source timestamps and indicators instead of these example dates.
Supported kinds: domain, ip, url, apk_sha256 and certificate_sha256. Classification
is a source assertion: malicious, suspicious, benign or unknown. Confidence is a
source label: low, medium, high or unknown; it is not measured detection accuracy.
Each record requires id, kind, value, classification, confidence and observed_at.
record.valid_until and reference are optional; feed.source_url is optional.
Timezone-aware timestamps are required. Record observation cannot follow feed
publication, and expiry must follow observation/publication as appropriate.
Unknown fields, duplicate JSON keys/record IDs and invalid indicators reject the
feed instead of silently dropping entries. At most 10,000 records are accepted.

## Operator configuration

Keep private feeds under an ignored data directory or another controlled local
folder. Validate before configuring:

```powershell
.\.venv\Scripts\python.exe -m godeep.integrations.intelligence.local_feed C:/private/feed.json
```

The command reports status, source metadata, counts and feed_sha256, without
querying a provider or printing all indicators. It succeeds only for a fresh,
valid feed. Set backend/.env or worker environment values:

```text
GODEEP_INTEL_FEED_PATH=C:/private/feed.json
GODEEP_INTEL_FEED_SHA256=THE_VALIDATED_64_CHARACTER_LOWERCASE_SHA256
```

Restart the worker after changing configuration. No feed configuration was added
on this development machine; synthetic test feeds are confined to test folders.
Pins detect file changes, not publisher authenticity. Check source ownership,
licensing, attribution and handling policy through your feed acquisition process.
After an intentional feed update, validate again and update the expected digest.
The worker reads feed bytes once under a size bound and validates those exact
bytes against the expected digest. Paths/pins are not accepted in API request
bodies and are not stored in public job config. Every result records the actual
feed digest and matched records. Operator runtime updates can affect retries;
old matching runs cannot be reproduced fully unless the original feed is retained.
Automatic feed archival, source signatures and refresh scheduling are future work.

## Matching and interpretation

Candidates include original APK SHA-256, extracted certificate SHA-256, and URL,
domain/IP strings from DEX and selected resources. A certificate match refers to
extracted metadata, not proof that certificate validly signed the APK. Some policy
domain declarations, encoded content and unsupported resource formats remain outside
the candidate profile. Read all upstream coverage before interpreting absence.

Matching is exact by kind and canonical value. Domains use case folding, IDNA and
trailing-dot removal; parent domains do not implicitly match subdomains. IPs use
canonical address formatting. SHA-256 is case folded. URL scheme/host are case
folded and host/IP normalized; numeric ports are normalized, but paths, query,
fragment, explicit default ports, percent encoding and empty-versus-slash paths
are preserved. Credentials, malformed values and URLs longer than 2,048 characters
are unsupported. There is no fuzzy, wildcard, CIDR or STIX-pattern evaluation.

Results retain candidate evidence, active source records, source timestamps and
references. Exact duplicate evidence is suppressed; capped evidence remains marked
truncated. Active benign-versus-adverse claims set feed_assertions_conflict; other
label differences remain visible through classification_labels_differ. Conflict is
checked before output caps. No source is silently chosen as the final verdict.
Expired records are excluded from active matches, with expired count and bounded
record IDs retained for review.

lookup_status is matched, no_match_in_local_feed, expired_indicators_only or
not_checked. No match means unknown within that feed, not safe. Static strings
do not prove contact with a destination or exfiltration. No risk score or malware
classification is generated by this adapter.

## Coverage and bounds

Feed status distinguishes not_configured, available, invalid_configuration,
feed_unavailable, feed_size_limit, feed_hash_mismatch, feed_invalid, feed_from_future,
feed_expired and feed_stale. Only available feeds are used. Others leave all
candidate lookups not_checked. Default maximum feed age is 30 days even if its
valid_until lies farther ahead. Expired indicators and capped output make matching
coverage partial, retaining the distinction from a full no-match operation.

Defaults: 2 MiB feed, 1,000 candidate groups, 50 active records per candidate and
the shared 50 evidence references per group. Retained expired record IDs are also
capped by max_intel_matches; total expired_match_count remains visible. These limits
are snapshotted with the job. A final result beyond the worker's output bound fails
explicitly. No configured feed is bundled in Git. Original phase observations,
resources and intelligence coverage remain separate in the combined result.

## Tests

Original synthetic fixtures test normalization, exact/subdomain matching, duplicate
evidence, conflicting and expired records, unavailable/stale/future/invalid feeds,
hash and size bounds, output caps, schema/timezone rules, CLI validation and a real
case-scoped worker pipeline. Existing real signature-tool tests remain enabled in
recorded full-suite runs. See [verification](postgresql-verification.md).
These establish functional matching, not feed truth or real-world detection accuracy.
