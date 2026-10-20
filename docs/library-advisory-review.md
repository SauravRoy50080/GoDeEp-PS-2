# Offline declared-library advisory review

The `library_review` adapter 1.0.0 inspects a hash-verified APK snapshot for
resource/library metadata and compares exact declared Maven coordinates/versions
with an optional pinned local feed. It adds source claims and evidence; it does
not establish that vulnerable code is packaged, reachable or exploitable.
No dependency or database migration is added.

Queue through the authenticated job API:

```json
{"sample_id": "SAMPLE-UUID", "adapter": "library_review"}
```

POST to `/api/v1/cases/{case_id}/analyses`, run the existing worker, poll the job
and retrieve `/result`. The authenticated analyzer catalog lists the adapter.
Select its completed job in the existing forensic report API to retain findings.
The all-adapter workflow test now includes eleven registered adapters. Comparison
still supports only static_review/threat_review. Priority scores and ML outputs
are unchanged.

## Feed v1

Create a private local JSON feed outside Git. The following is synthetic, not a
real CVE assertion. Replace source records and validity dates with reviewed data.

```json
{
  "schema_version": 1,
  "feed_id": "your-library-feed-v1",
  "source_name": "Reviewed advisory source",
  "published_at": "2026-10-21T00:00:00Z",
  "valid_until": "2026-10-22T00:00:00Z",
  "advisories": [
    {
      "id": "SYNTHETIC-EXAMPLE-1",
      "group_id": "org.example",
      "artifact_id": "demo",
      "versions": ["1.2.3"],
      "assertion": "affected",
      "title": "Synthetic example only",
      "reference": "https://example.org/advisory",
      "withdrawn": false,
      "valid_until": "2026-10-22T00:00:00Z"
    }
  ]
}
```

Assertion is `affected` or `not_affected`. `versions` lists the exact strings to
which that assertion applies. Advisory record validity/reference are optional;
feed publication/expiry are mandatory and timezone-aware. Advisory IDs and exact
versions within a record must be unique. At most 5,000 records, 100 versions per
record and 50,000 expanded coordinate/version keys are allowed. Extra fields,
duplicate JSON keys, non-finite numbers and boolean schema versions are rejected.
The custom format is not a native OSV/NVD feed; external import/range conversion
is not implemented. Operator conversion must preserve advisory semantics.

Validate the local file without network requests:

```powershell
.\.venv\Scripts\python.exe -m godeep.integrations.intelligence.library_feed C:\private-feeds\libraries.json
Get-FileHash C:\private-feeds\libraries.json -Algorithm SHA256
```

Pin the exact byte hash (lowercase) and absolute path in private backend/.env:

```dotenv
GODEEP_LIBRARY_FEED_PATH=C:/private-feeds/libraries.json
GODEEP_LIBRARY_FEED_SHA256=REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS
GODEEP_LIBRARY_FEED_MAX_AGE_DAYS=30
GODEEP_MAX_LIBRARY_FEED_BYTES=2097152
GODEEP_MAX_LIBRARY_MATCHES=20
```

Restart API/worker after configuration changes. Matching controls are snapshotted
in the job, while private feed path/hash enter only the trusted library adapter
runtime. Result provenance records the feed's actual hash and source metadata.
No feed path appears in public job configuration or library result metadata.
Retain the reviewed feed bytes independently for reproduction. A matching hash
establishes consistency with operator configuration, not advisory truth.

## Matching and interpretation

Only `maven_properties` observations with matching embedded group/artifact path
identity are eligible. Coordinates and version strings match exactly and
case-sensitively. No normalization, Maven range evaluation, version aliasing,
transitive resolution, code fingerprinting or recursive extraction occurs.
Standalone version markers and path conflicts are retained as unresolved rather
than guessed. Resource parse/selection limits remain visible.

Repeated coordinate/version declarations are grouped with member paths and
member hashes. Identical member/hash evidence does not add independent votes.
Evidence is capped by the existing max_review_evidence setting; match records
are capped by max_library_matches. Counts/truncation remain explicit.

Future, expired, stale, unavailable, malformed, oversized or hash-mismatched feeds
produce not_checked coverage, not a safe verdict. Defaults without a configured
feed still permit resource inspection. Withdrawn and expired individual claims
are excluded and counted. Conflict detection uses all active records before
output truncation, so affected/not_affected conflicts cannot disappear simply
because fewer records are displayed. Conflicts remain source claims for review;
there is no automatic majority vote or score.

Lookup status distinguishes matched source claims, no exact match in this local
feed, excluded-only claims and not checked. A no-match result means unknown within
this feed. Even a not_affected source assertion is not proof that the APK is safe.
Normal matches retain identity_verified=false and requires_review=true. The
inventory's vulnerability_status points to see_library_review; source declarations
are retained unchanged in meaning and the standalone inventory adapter is unchanged.

Coverage is complete only for this selected exact-declaration lookup when resources
and output are complete; it is never full software-composition coverage. Existing
resource, worker timeout and total result-size bounds still apply. All imported
advisory title/reference text is untrusted evidence for future UI rendering.

Implementation uses synthetic test advisories only. No production feed has been
configured and no real dependency/CVE match is claimed. No APK or package metadata
is submitted externally. Live Android execution, full SCA, verified packaged code,
version-range matching and exploitability assessment remain pending.
