# Imported runtime observation captures

This milestone adds a case-scoped API for bounded structured runtime observations.
It does not install or execute APKs, control devices, verify isolation or prove
that the collector ran the selected APK. The collector asserts input hash,
package, times, environment and event attribution. Original evidence integrity is
checked at import, but association with runtime events is not independently verified.

ADB/emulator were not found on PATH or in the standard local Android SDK locations
during implementation. Live collection remains pending; tests use synthetic traces.

## Apply the additive migration

From the repository terminal, with your development PostgreSQL running:

```powershell
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini current
```

Expected revision: `0005_runtime_captures`. Restart the API afterwards. The
migration adds a separate table; original sample, analysis and report data are
preserved. Upgrade/downgrade and schema checks run on isolated SQLite/PostgreSQL
in testing, not on the user's application database. No new package is required.

## API

All routes require a bearer session and use:
`/api/v1/cases/{case_id}/samples/{sample_id}/runtime-captures`

| Method / suffix | Purpose |
|---|---|
| POST base | Import a raw application/json trace; owner/analyst only |
| GET base | Paginated metadata list, limit 1-100, offset >=0 |
| GET /{capture_id} | Case/sample-scoped metadata and summary |
| GET /{capture_id}/download | Hash/size-verified original trace bytes |

Viewers may read permitted captures but cannot import. Case access is checked
before body streaming and again before persistence. Capture IDs cannot be used to
cross cases or samples. No update/delete route is supplied.

## Trace v1 example

Use the registered sample SHA-256 in place of the placeholder. This is a synthetic
example describing a collector claim, not proof that a process contacted an IP.

```json
{
  "schema_version": 1,
  "input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "source_run_id": "collector-run-001",
  "collector": {"name": "your-collector", "version": "1.0"},
  "environment": "emulator",
  "package_name": "org.example.application",
  "started_at": "2026-10-21T10:00:00Z",
  "ended_at": "2026-10-21T10:00:10Z",
  "collection_status": "partial",
  "coverage": {
    "process": "partial",
    "filesystem": "not_collected",
    "network": "collected",
    "sensitive_access": "not_collected"
  },
  "events": [
    {
      "event_id": "00000000-0000-4000-8000-000000000001",
      "timestamp": "2026-10-21T10:00:01Z",
      "pid": 123,
      "kind": "network",
      "transport": "tcp",
      "destination_ip": "192.0.2.1",
      "destination_port": 443
    }
  ]
}
```

The full structural contract is [runtime-trace.schema.json](runtime-trace.schema.json).
Chronology/coverage constraints below are enforced by model validation beyond
JSON Schema. Input names/paths are evidence strings and must be escaped by clients
when rendered; they are never executed or opened by the API.

Four event kinds are supported:

- `process`: start/stop and process name.
- `filesystem`: create/read/write/delete, path and optional collector-asserted content SHA-256.
- `network`: TCP/UDP, destination IPv4/IPv6 and port 1-65535.
- `sensitive_access`: camera/microphone/location/contacts/SMS plus an operation description.

Every event has UUID event_id, timezone-aware timestamp and positive integer pid.
Events must be ordered within the inclusive collection interval, have distinct IDs
and agree with coverage: a `not_collected` stream cannot contain events. Collection
intervals span zero through 24 hours. Timezone offsets are preserved; collector
clock accuracy is not verified. Negative or oversized values, unknown fields,
duplicate JSON keys, non-finite numbers and unsupported event variants are rejected.

Collection status is completed/partial/failed. Each stream's coverage is separately
collected/partial/not_collected. A completed collection may still have uncollected
streams. Even `collected` does not prove instrumentation completeness. Empty events
or a zero per-kind count never establish absence of runtime activity.

## Bounds, provenance and storage

The default streamed request cap is 2 MiB, configurable using
`GODEEP_MAX_RUNTIME_CAPTURE_BYTES` (1 KiB through 10 MiB). There are at most 2,000
events and bounded string fields. The original APK's current bytes/hash/size are
verified before import. The trace input hash must match that sample's recorded
SHA-256; mismatches return 409. Package identity is retained as a collector claim
and is not cross-verified against the manifest.

Exact submitted bytes are stored exclusively, hashed and referenced from metadata.
A database transaction records the capture and import audit event. Failed writes
or transactions clean up newly owned artifacts; ID collisions preserve existing
files. Identical bytes cannot be imported twice for the same sample (409). Rewritten
or differently formatted traces can have different hashes and are not independent
confirmation; source_run_id is a collector reference, not an idempotency guarantee.

Metadata summarizes event counts, collector, environment, period, coverage and
`attribution=collector_asserted_not_verified`, `isolation=not_verified`. It includes
an original-integrity check timestamp. Metadata reads do not reverify trace bytes;
downloads verify hash and length every time and fail closed on tampering or loss.
Downloads send no-store, nosniff and X-Capture-SHA256 headers. Data and staging
artifacts remain under ignored backend/data storage, not Git.

These controls provide integrity relative to metadata, not tamper-proof custody,
trusted collector signatures or legal certification. OS-level sandbox execution,
collector adapters, packet capture, event correlation, intelligence enrichment and
inclusion in forensic report snapshots remain pending. Current report selection
still accepts analysis jobs only; captures do not modify scores or classifier
predictions. Raw logs/PCAP/binary uploads are not accepted by this endpoint.
