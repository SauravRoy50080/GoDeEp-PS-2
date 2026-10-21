# Static/runtime IP co-occurrence

Backend 0.26.0 adds a read-only evidence view over a selected combined forensic
report. Create a version-2 report containing at least one `static_review` 1.0.1
or `threat_review` 1.0.0 job and at least one imported runtime capture, then call:

`GET /api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}/network-correlation?limit=100&offset=0`

Bearer authentication and existing case/sample/report permissions apply. Case
viewers can read. There is no frontend change, external request, DNS resolution,
new job, report, audit write, database migration or model/priority score change.

## Interpretation

The view groups emitted static IP candidates and typed network-event destination
IPs by canonical numeric IPv4/IPv6 identity. Existing static extractors can emit
IP candidates from IP-literal URL hosts. Domain and URL candidates themselves are
skipped and counted; no domain-to-IP relationship is inferred. Scoped addresses
are excluded. IPv4-mapped IPv6 addresses remain distinct from IPv4. Matching ignores
port/transport, while collector evidence retains these fields.

Each IP has one of three relationships:

- `in_both_selected_sources`: present in supported static candidates and imported
  collector events in this snapshot.
- `static_only_in_selection`: present in selected static candidates only.
- `collector_only_in_selection`: present in selected collector events only.

These are record co-occurrences, not proof of execution, reachability, successful
network contact, malicious intent, data flow or exfiltration. Runtime package,
process, clock, attribution and isolation remain collector assertions. An unmatched
IP only means no matching record was found in this selection. Partial collection,
truncated extraction, encrypted/loaded payloads, unsupported analyzers and untested
paths can all hide activity. Repeated observations and overlapping analyzers are
retained as separate records, not independent evidence votes.

## Evidence and coverage

Every static reference contains its job ID, exact source result hash and JSON
pointer into the persisted report. Every collector reference contains capture ID,
original trace hash, event ID, timestamp, PID, transport, destination port and a
JSON pointer into the report's normalized trace. Event IDs/PIDs are not joined
across captures. Repeated candidates from one job are counted separately, including
multiple static representations of the same address. Counts are occurrence counts.

`source_report_sha256` identifies the exact persisted report bytes. JSON pointers
refer to that report, not to original trace bytes: normalized trace serialization
can differ from its original imported representation. Source coverage, collection
status and static source limitations remain visible. Other adapter/version pairs
are listed as `unsupported_adapter_version` and are not inspected or counted as
negative evidence. The view has `correlation_version: 1.0.0` and explicitly limits
its scope to selected supported sources.

The existing report download service checks artifact hash/size and authorization.
The view also checks report/case/sample identity, supported static result identity
and embedded trace schema/input/run identity. It does not re-read original APKs,
feed files or upstream source artifacts. Those were checked at snapshot creation;
a valid historical report can still be read after an upstream artifact is lost.
Hashes compared with database metadata do not provide tamper-proof custody.

## Bounds and errors

Items are sorted numerically by IPv4 first, then IPv6. `limit` defaults to 100,
maximum 200; `offset` ranges from 0 through 20000. Summary totals and occurrence
counts cover all selected supported sources, regardless of the current page.

| Setting | Default | Allowed range |
|---|---:|---:|
| `GODEEP_MAX_NETWORK_CORRELATION_GROUPS` | 5000 | 1–20000 |
| `GODEEP_MAX_NETWORK_CORRELATION_CANDIDATES` | 20000 | 1–100000 |
| `GODEEP_MAX_NETWORK_CORRELATION_EVIDENCE` | 25 per IP per side | 1–100 |
| `GODEEP_MAX_NETWORK_CORRELATION_BYTES` | 1048576 | 1024–5242880 |

The candidate budget counts all scanned static IP/domain/URL candidate records.
Group or candidate overflow fails with 413, rather than dropping IP relationships.
Evidence retention alone is capped: full occurrence counts and explicit per-group
and overall `evidence_limited` flags remain. Smaller pages can reduce response size
but do not bypass source/group/candidate limits. Existing report source byte limits
and imported trace event bounds still apply; rendering is in memory.

Invalid queries return 422; inaccessible/mismatched case/sample/report paths return
404; missing required supported static/runtime sources, invalid snapshot identity,
invalid embedded traces or tampered reports return 409. Oversized responses return
413. No empty response should be interpreted as a clean malware verdict.
