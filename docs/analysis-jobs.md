# Milestone 3: durable analysis jobs and archive inventory

## Implemented scope

A PostgreSQL-backed queue accepts case-scoped analysis jobs. A separately started
worker claims jobs and runs the registered adapter in a bounded subprocess.
No Redis/Celery service is required; install the declared Python dependencies.
SQLite supports local functional tests; use PostgreSQL for concurrent workers.

The default adapter is `archive_inventory` version `1.0.0`. It verifies the original
SHA-256, creates a bounded temporary snapshot, performs the existing ZIP-container
checks, and reports counts and bounded path lists for DEX/native-library entries.
It does not parse manifest/DEX contents, verify Android signatures, identify malware,
assign risk scores, or execute an APK. A `completed` job means this adapter finished,
not that a security assessment is complete or the app is safe.

The second adapter, `android_static`, extracts manifest and certificate evidence.
See [Android static analysis](android-static-analysis.md). Authenticated
`GET /api/v1/analyzers` lists implemented capabilities.

## Start the API and worker

From repository root with the database configured in `backend/.env` (or
`GODEEP_DATABASE_URL`) and a user already provisioned:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m uvicorn godeep.main:app --app-dir backend/src --host 127.0.0.1
```

In a second terminal, from the same root and with the same database/evidence settings:

```powershell
.\.venv\Scripts\python.exe -m godeep.workers.runner
```

For scripts or a single processing cycle:

```powershell
.\.venv\Scripts\python.exe -m godeep.workers.runner --once
```

The API never runs jobs in its request process. If no worker is started, jobs stay
queued. A worker prints no sample content, passwords or session tokens. Use API
status and audit events to inspect processing outcomes. Ctrl+C stops polling;
an interrupted claimed job is recovered through its lease as described below.

## API contract

All routes require a bearer token and existing case access. Owner/analyst can
submit, cancel and retry; viewers can read status/results. Inaccessible cases and
cross-case job IDs return 404. Unknown adapter names return 422.

| Method | Path | Result |
|---|---|---|
| POST | `/api/v1/cases/{case_id}/analyses` | 202, queued job |
| GET | `/api/v1/cases/{case_id}/analyses` | Paginated jobs |
| GET | `/api/v1/cases/{case_id}/analyses/{job_id}` | Status and provenance |
| POST | `/api/v1/cases/{case_id}/analyses/{job_id}/cancel` | Cancel queued/running job |
| POST | `/api/v1/cases/{case_id}/analyses/{job_id}/retry` | 202, a distinct retry job |
| GET | `/api/v1/cases/{case_id}/analyses/{job_id}/result` | Verified JSON result for completed job |

Submission body:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"archive_inventory"}
```

Submit after registering an APK and poll the returned job ID. Running status
does not invent a percentage. The response records adapter/version, source hash,
submission-time archive bounds/timeout configuration, requester, attempt number
and lifecycle timestamps. Internal storage keys and worker claim tokens are hidden.
See Swagger `/docs` for the exact response fields.

For archive inventory, result data includes `schema_version`, adapter identity, input hash/size,
`observations` (entry/file counts, declared expansion, DEX/native-library counts,
bounded path lists and top extensions), and explicit limitations. It contains no
malware verdict. Path strings are untrusted evidence text and must not be rendered
as HTML by a future frontend.

## Lifecycle, concurrency and recovery

```text
queued -> running -> completed
                  -> failed
queued/running -> cancelled
failed/cancelled -> explicit retry (new ID, linked to original)
```

- PostgreSQL workers select queued rows with `FOR UPDATE SKIP LOCKED`, then use a
  conditional update to claim them. A per-claim token prevents stale completion.
- Worker execution uses a monotonic wall-clock deadline (default 60 seconds).
  Each claim has a database lease expiring 30 seconds after that configured limit.
  Worker clocks must be synchronized for lease interpretation.
- Cancel marks the database job cancelled immediately. The active worker checks
  its claim between subprocess polls and kills the current child when it observes
  cancellation. It does not publish a late result. This is cooperative cancellation,
  not a guarantee of zero delay or a whole-process-tree containment mechanism.
- Each polling cycle marks up to 100 expired running jobs failed with
  `worker_lease_expired`. If all workers are offline, expiry is reflected when a
  worker next polls. There is no automatic re-execution of forensic work.
- Retry is explicit, supports at most three attempts in a chain, and preserves
  the original adapter version/configuration. Each parent may have only one retry.
  Failed/cancelled historical records stay intact. A new analysis can be requested
  independently when configuration or installed adapter versions change.
- Queue/cancel/retry/start/terminal transitions create transactional case audit
  events. Authenticated UUIDs identify user actions; `analysis-worker` identifies
  the trusted worker process, not a separately authenticated worker identity.
- Authorization governs submission and result access. Queued work is not automatically
  withdrawn when its requester is later disabled or removed; an authorized case
  owner/analyst must cancel it. Workers act as trusted local infrastructure.

## Result evidence

Successful adapter JSON is kept under an opaque job/claim-derived artifact key.
Its SHA-256 is recorded with the completed job. The API reads a bounded result and
re-verifies its digest before returning it. Missing/altered results return 409,
rather than silently replacing evidence. Original-byte hash mismatches fail the job.
Temporary snapshots are removed after ordinary success, cancellation or failure.

Filesystem publication and database commit are not one atomic distributed
transaction. Process/host crashes can leave orphaned staging or result files;
reconciliation and disaster recovery remain future work. A persisted job is not
an exactly-once execution guarantee. No automated cleanup of unexplained evidence
is provided. Local files remain mutable outside the application.

## Isolation and operational limits

A subprocess is **not a malware sandbox**. This worker has the host user's privileges
and does not supply OS-level network/memory/CPU isolation. It runs only the trusted
built-in static adapters and optional trusted apksigner integration, uses no shell command assembled from input,
and does not execute APK code. External tools and dynamic APK execution must not
be added here without the dedicated isolation layer planned for later milestones.

Output is capped at 1 MiB after subprocess completion. The built-in adapters emit
bounded lists and no raw decompressed content; this is not a general disk quota
for future analyzer processes. Wall-clock timeouts are not memory limits. Database
connection failures may stop the worker; after database recovery restart it and
allow leases to expire. Queue quotas and production worker supervision are pending.

Settings: `GODEEP_JOB_TIMEOUT_SECONDS`, `GODEEP_WORKER_POLL_SECONDS`, and
`GODEEP_MAX_RESULT_BYTES`. The worker and API must use the same metadata database
and evidence directory. Input limits are snapshotted at submission; output safety
limits are operational settings and are enforced by the current worker/API.

## Verification

Tests cover real subprocess inventory, job API permissions, integrity checks,
explicit retries/limits, cancellation, expired leases, output limits and worker CLI.
Timeout handling is tested with an injected non-terminating process double.
Live PostgreSQL adds simultaneous worker claims and a cancel/terminal-transition race.
Run the suite using [PostgreSQL test setup](postgresql-verification.md).

The dex_static adapter adds bounded identifier-table triage; see
[DEX analysis](dex-static-analysis.md). The dex_calls adapter adds [instruction evidence](dex-call-analysis.md).
The static_review adapter adds [unified findings](unified-static-review.md).
The signature_verify adapter adds [official signature verification](signature-verification.md).
All six adapters use the same worker; verification requires configured external tools.
