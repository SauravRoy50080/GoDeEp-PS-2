# Structured forensic report snapshots - milestone 11

## Database update

This step adds migration 0004_forensic_reports. Stop/restart application processes
around your normal database deployment workflow and apply it before using reports:

```powershell
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
```

The migration adds a report table/indexes without rewriting existing cases,
samples, users or analysis jobs. No new Python dependency is required. Verification
uses isolated test databases; the development runtime database is not migrated
automatically by this implementation step. Deployment backup/restore remains an
operator responsibility. Downgrading removes report metadata; artifact retention
and reconciliation are not automatically managed by Alembic.

## API

All routes require a bearer session and case/sample access:

| Method | Path | Purpose |
|---|---|---|
| POST | /api/v1/cases/{case_id}/samples/{sample_id}/reports | Create persisted snapshot |
| GET | /api/v1/cases/{case_id}/samples/{sample_id}/reports | Paginated report metadata |
| GET | /api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id} | Read metadata |
| GET | /api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}/download | Verified JSON download |

Owners/analysts create reports. Authorized viewers can list, read and download.
Cross-case/sample report IDs and unauthorized cases return 404. Viewers cannot
create reports. Metadata excludes internal artifact paths.

Creation body:

```json
{"job_ids":["COMPLETED_ANALYSIS_JOB_UUID","ANOTHER_COMPLETED_JOB_UUID"]}
```

Select 1-20 distinct completed jobs for exactly this registered sample. Jobs from
a separate registration are rejected even when original bytes have the same hash.
The API does not silently pick a latest run or rerun analysis. Source IDs are sorted
for a stable selection order. Each successful request creates a new report ID;
there is no idempotency-key or report deletion/update API at this stage.

Response 201 includes report ID, creator UUID, timestamp, source-job IDs, input
SHA-256, report SHA-256 and byte size. Download returns the exact persisted UTF-8
JSON bytes as an attachment with X-Report-SHA256, no-store and nosniff headers.
Download filenames contain only a server-generated report UUID. Filenames and
analysis text inside the document remain untrusted evidence text; future viewers
must escape them when displaying HTML.

## Content and evidence

The document is an investigation_analysis_snapshot containing:

- Case identity/name/description and registered sample identity, original name,
  SHA-256, byte size and original-byte verification time.
- Report ID, schema version, generated time and creating user UUID.
- Explicitly selected source job IDs, analysis count and selection scope.
- Each source adapter/version, completion time, recorded configuration, result
  hash and complete JSON analysis data, including tools, evidence and coverage.
- Limitations about overlapping evidence, partial runs and snapshot interpretation.

A completed analysis can contain a failed phase, unavailable tool/feed or partial
coverage; those states are preserved without a new clean verdict. Overlapping
adapters can repeat observations. Reports do not sum findings into a risk score,
count duplicate tool output as independent confirmation or add an AI narrative.
No analyst approval, examiner signature or legal certification is implied.
This first export is JSON; HTML/PDF templates, evidence graphs, comparison reports,
analyst review-state persistence and signed/tamper-evident reporting remain future work.

## Integrity, persistence and limits

At creation, the original APK is streamed and checked against recorded size and
hash under the current upload bound. Selected analysis artifacts are read under
the current result-size bound, rehashed against job metadata and checked for
matching schema/adapter/version/input identity. Missing/altered originals or
results return 409; incomplete jobs also return 409. Unknown/cross-sample sources
return 404; duplicate/empty/oversized selections return validation errors.

The report uses strict JSON serialization, an exclusive new artifact file and a
stored SHA-256. At most 20 source results and 10 MiB report output are allowed by
default. Aggregate source bytes and final rendered bytes are bounded. Exceeded
report bounds return 413 without a partial report. GODEEP_MAX_REPORT_BYTES is an
operational setting, not a per-request override. Creation currently runs in the
API thread pool; production quotas and an asynchronous export queue remain future work.

Report metadata and report.created audit metadata commit in one database transaction.
Ordinary transaction failures remove the newly written artifact. An existing report
artifact is never overwritten or removed by a failed ID-collision attempt. Filesystem
publication and database commit are not one atomic distributed transaction: a hard
crash can leave orphaned files or missing artifacts requiring reconciliation.
No automated deletion of unexplained report/evidence files is supplied.

Downloads verify report bytes against the stored hash and size. They do not recheck
original/source files or rerun analyzers: a snapshot remains downloadable after
later source changes, while a new report would recheck those sources. Missing or
altered report bytes return 409. Metadata reads/listing describe database records;
only download verifies current artifact bytes. Download access events are not
separately audited in this step. Creation audits record actor, sample, sources and hash.

Hashes are integrity checks relative to mutable database records, not digital
signatures or tamper-proof custody. Production object immutability, full access
auditing, backup/recovery and disaster-recovery exercises remain separate work.

## Verification

Tests cover real report generation/download, exact byte hashes, selection validation,
same-hash separate samples, roles/case scoping, tampered/missing artifacts, original
changes, output limits, database rollback cleanup, ID collisions and retention of
unavailable analysis states. Upgrade from the prior schema preserves existing jobs;
Alembic schema consistency and broader upgrade/downgrade tests run on SQLite and
live PostgreSQL. Results are recorded in [verification](postgresql-verification.md).
