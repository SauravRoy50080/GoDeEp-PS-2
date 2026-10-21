# Evidence-linked analyst reviews

Backend 0.33.0 adds ten connected features: append-only entries, exact evidence
pointers, report/source hash binding, review decisions, preserved corrections,
paginated history, current thread heads, transactional audits/conflict handling,
JSON export and printable HTML export. Reviews remain separate from forensic
report bytes and automatic findings. No new dependency or frontend is added.

## Apply migration first

From the repository root with the development PostgreSQL available and the same
database configuration used by the API:

```powershell
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
```

The new head is `0006_report_reviews`. It adds report_review_entries and an internal
per-report allocation counter. Existing report hashes, artifact bytes and source
selection remain unchanged. Test databases exercise upgrade/downgrade; the running
application database is not migrated automatically by API startup. Downgrading
removes review history and its counter; preserve exports before any intended downgrade.

## API

All routes have this prefix:

```text
/api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}
```

| Route | Behavior |
|---|---|
| POST /reviews | Append a root entry or a complete replacement revision |
| GET /reviews | Paginated history; optional current=true and thread_id |
| GET /reviews/export/json | Complete bounded history with current entry IDs |
| GET /reviews/export/html | Printable complete history, identifying superseded/current entries |

A bearer token and case membership are required. Owner/analyst roles may append;
viewers may read/export. Only the original thread author or case owner may revise
a thread, and both still require current write permission. An analyst can create
an independent disagreeing thread. Revising somebody else's thread requires owner
rights. The original author may revise a later owner correction in their own thread.
There are no update/delete operations. A correction references the current head;
stale corrections return 409. Parent entries from another report return 404.

Example POST body (replace hashes and UUIDs with the selected report's actual values):

```json
{
  "expected_report_sha256": "REPORT_SHA256",
  "decision": "follow_up",
  "text": "Review the recorded API observation with its benign framework context.",
  "evidence_references": [
    {
      "source_kind": "analysis",
      "source_id": "JOB_UUID",
      "pointer": "/analyses/0/data/coverage"
    }
  ]
}
```

Expected hash is required and must match the verified report bytes. Decisions are
comment, supported, disputed or follow_up. Non-comment decisions require at least
one reference. Comments may have no references. Text is 1–4000 characters, not blank,
with valid Unicode scalar values and no NUL. Up to ten distinct references are
accepted; each pointer is at most 1024 characters and 32 path tokens.

A revision sends the same complete body plus supersedes_id set to the current head
entry's UUID. It replaces that thread's current text/decision/references; omitted
references are not inherited. A comment revision can explain withdrawal of an earlier
decision. The original entry remains unchanged and retrievable in history. Account
ID, timestamp, thread ID and predecessor ID are retained. No decision votes, automatic
risk updates, report approval, malware verdict or consensus are inferred.

## Evidence reference rules

References identify source_kind (analysis or runtime_capture), source_id and an exact
JSON pointer within that source's normalized data in the selected report:

```text
/analyses/0/data/...
/runtime_captures/0/data/events/0
```

Pointers to report metadata or sources outside the report are rejected. IDs must match
the addressed source; source hash, sample hash and analysis adapter identity are
checked. Runtime traces are schema/identity validated. Empty key tokens are supported
when they address real object keys. Array indices have no leading zeros; unresolved
indices and '-' are rejected. Token escapes follow [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901):
~1 is decoded before ~0. URI-fragment pointers and Unicode normalization are excluded.
Pointers with NUL or surrogate code points are not accepted.

The server stores the source result/trace hash and a hash of the referenced normalized
value, encoded with Python sorted-key, ASCII-escaped strict JSON (sorted_ascii_json_v1).
This is a versioned implementation encoding, not a claim of cross-language canonical
JSON. It stores a digest rather than duplicating source content. Original trace hashes
identify original bytes; JSON pointers identify embedded normalized snapshot values.

Reads verify the report hash/size and source identity, then revalidate stored bindings
and thread lineage before pagination. A changed report, mismatched binding, missing
parent, fork or cycle is rejected. Original APKs and external source artifacts are
not re-read after report creation. A hash binds a judgment to recorded evidence;
it does not establish independent confirmation or collector attribution.

## History, current view and exports

GET /reviews accepts limit 1–100 (default 25), offset 0–2000 (default 0), current
(default false) and optional thread_id. History ordering is recorded timestamp then
entry UUID. Thread predecessor IDs, rather than host clock ordering, define revisions.
current=true returns the unsuperseded head of each selected thread. Multiple current
threads may conflict. Export JSON includes all bounded history and current_entry_ids;
HTML labels current and superseded entries. Exports are derived downloads and do not
create new persisted forensic snapshots or review entries.

JSON and HTML carry no-store, nosniff, source report SHA256, export SHA256 and review
version headers. HTML escapes source/analyst strings, has no active links, scripts or
remote resources, and sends restrictive CSP/frame/referrer headers. It includes the
JSON export digest and can be browser-printed. These are account-authored judgments,
not digital signatures, legal attestation or tamper-proof custody. The API is
append-only; privileged database manipulation is not cryptographically prevented.

## Transactions and bounds

Entry insertion, internal report-counter increment and report.review_appended audit
record commit together. The counter is allocated through a conditional SQL update;
a unique predecessor constraint prevents concurrent correction forks. Errors roll
back the allocation and row/audit together. After ambiguous connection failures,
reload history before retrying. Storage unavailability returns sanitized 503 and
concurrent/stale conflicts return 409. Unauthorized objects return 404; insufficient
case permissions return 403; invalid bodies/pointers return 422.

| Setting | Default | Scope |
|---|---|---|
| GODEEP_MAX_REPORT_REVIEW_ENTRIES | 500 | Total entries, including revisions, per report |
| GODEEP_MAX_REPORT_REVIEW_REFERENCE_BYTES | 16777216 | Serialized referenced values per request, with repeated-pointer cache |
| GODEEP_MAX_REPORT_REVIEW_BYTES | 4194304 | JSON list/export response |
| GODEEP_MAX_REPORT_REVIEW_HTML_BYTES | 16777216 | HTML export response |

Maximum settings are 2000 entries, 64 MiB reference values, 16 MiB JSON and 32 MiB
HTML. The existing report byte bound applies first. Reads scan at most the entry
budget plus one and reject excess. Full history/bindings are validated before paging;
a smaller page only helps response-size limits. Prefer precise leaf pointers over
large subtrees to stay within reference budgets. Over-budget work returns 413 rather
than silently dropping history. Lowering limits can make existing history temporarily
unreadable until limits are restored. Entries and audits are stored in PostgreSQL/
SQLite metadata, so database backups must retain both alongside report artifacts.

Live emulator containment, additional runtime collectors, formal report sign-off and
externally validated ML remain pending. This milestone improves analyst investigation
and review traceability, without establishing malware-detection accuracy.
