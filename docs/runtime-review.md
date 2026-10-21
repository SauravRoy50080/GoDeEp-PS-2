# Runtime evidence review and comparison

Backend 0.31.0 adds seven connected capabilities: process, filesystem, network and
sensitive-resource inventories; sparse elapsed activity buckets; exact two-capture
comparison; and authenticated JSON/printable HTML views. These views consume
existing version-2 forensic report snapshots. They do not start a sandbox, collect
new device data, change reports or run a model. No migration or dependency is needed.

## Workflow and routes

Upload a trace through existing authenticated runtime intake, then create a report
selecting its capture ID. A report may contain runtime sources alone or alongside
static jobs. The passive process collector can supply process observations; the
other streams currently require separately supplied collector traces. Creating a
review does not upgrade any collector's attribution or isolation claim.

Use this prefix (all IDs are UUIDs):

```text
/api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}
```

| Method and suffix | Purpose |
|---|---|
| GET /runtime-review | Inventory or elapsed activity page |
| GET /runtime-review/export/html | Printable version of the same selected page |
| GET /runtime-comparison | Compare exact identities in two selected captures |
| GET /runtime-comparison/export/html | Printable comparison page |

All routes require a bearer token and case membership; viewers may read them.
Case/sample/report associations are checked before evidence is read. The existing
report hash and size are checked, followed by snapshot identity, bounded source
count, unique capture IDs, trace identity and schema validation. Invalid snapshots
return 409; unavailable/unauthorized resources return 404 (missing login 401).
Unknown or unselected capture IDs return 404. These checks validate the recorded
snapshot; they do not re-read original APKs or source captures after report creation.

Review query parameters:

| Parameter | Values/default |
|---|---|
| section | process (default), filesystem, network, sensitive_access, activity |
| capture_id | Optional one capture already selected in this report; omitted means all |
| bucket_seconds | 1–3600, default 10; used only for activity |
| limit | 1–200, default 100 |
| offset | 0–40000, default 0 |

Comparison requires left_capture_id and right_capture_id, distinct captures already
selected in the same report/sample. It supports the four inventory sections and
limit/offset; activity comparisons are not accepted. Invalid query values return 422.
Example query suffixes:

```text
/runtime-review?section=network&limit=50
/runtime-review?section=activity&bucket_seconds=5&capture_id=CAPTURE_UUID
/runtime-comparison?section=filesystem&left_capture_id=LEFT_UUID&right_capture_id=RIGHT_UUID
```

Use the matching /export/html route with the same query to print that page.
JSON is also an attachment. Both formats send no-store, nosniff, source-report
SHA256, export SHA256 and view version headers. HTML escapes every collector string,
contains no scripts, external resources or active links, and has a restrictive CSP.
The HTML includes the derived JSON hash. These are derived exports, not new persisted
forensic reports, signed evidence, analyst sign-off or legal certification.

## Exact inventory semantics

| Section | Group identity |
|---|---|
| process | Exact process name + action (start, stop or observed) |
| filesystem | Exact path + operation + optional content SHA256 |
| network | Canonical IP representation + destination port + transport |
| sensitive_access | Exact resource + operation string |

Counts include repeated records. PIDs are retained in evidence references and are
not used to join process lifetimes or match captures. An observed event means presence
in a snapshot, never a start or stop. File paths are not resolved or normalized;
a path containing .. remains distinct. Null and specified content hashes remain
distinct and content is not opened. IP spellings normalize through the existing
trace schema, without DNS, ASN, reputation, routing or destination contact. Ports
and transports remain distinct; IPv4 and IPv4-mapped IPv6 are not merged. Scope IDs,
if accepted by the trace schema, remain part of the IP string. Network observations
do not prove a successful connection, data transfer or exfiltration. Sensitive
operations remain collector assertions. No risk score or malware verdict is added.

Each response retains report/case/sample identity, original APK hash, source report
hash, source trace hashes, source_run_id, collector/environment/package, source
coverage and collection status. Every retained evidence reference identifies the
capture, event, PID, timestamp and JSON pointer into the normalized report. Original
trace hashes identify original bytes; pointers address normalized embedded data.
Evidence samples are the first configured number per group across selected captures,
not a balanced sample or independent confirmation. Full counts are preserved and
evidence_limited is explicit; inspect the source traces for omitted references.

first_observed_at/last_observed_at are extrema of UTC-normalized collector timestamp
labels. They do not synchronize devices or establish causal ordering. Repeated names,
package strings and PIDs do not verify APK ownership, UID identity or execution.

## Activity and comparison interpretation

Activity uses sparse half-open elapsed intervals [start,end) relative to each
capture's own started_at. Captures are separate; no cross-device clock alignment
is attempted. A boundary event belongs to the next bucket, including an event at
the trace's inclusive ended_at. Thus a bucket may extend beyond collection end.
Empty intervals are not emitted and must not be interpreted as inactivity. Each
bucket includes per-kind counts and bounded event references. Sorting is capture ID
then numeric elapsed start; inventories use deterministic serialized-identity order.

Comparison returns both_selected_captures, left_selection_only or right_selection_only,
with left_count, right_count and count_delta (right minus left). Matching uses exact
inventory identities, without PID joins, duration/rate normalization, causality or
independent confirmation. Different capture durations/coverage can explain count
differences. A failed or partial source remains explicitly failed/partial; zero or
missing records mean absent in this selection only. All source statuses and coverage
remain visible, including not_collected streams. Duplicate source-run claims remain
separate captures and are not treated as corroboration.

## Bounds and persistence

| Environment setting | Default | Purpose |
|---|---|---|
| GODEEP_MAX_RUNTIME_REVIEW_EVENTS | 40000 | All selected events scanned, including other sections |
| GODEEP_MAX_RUNTIME_REVIEW_GROUPS | 2000 | Maximum distinct groups/buckets |
| GODEEP_MAX_RUNTIME_REVIEW_EVIDENCE | 5 | Retained references per group |
| GODEEP_MAX_RUNTIME_REVIEW_BYTES | 2097152 | JSON response cap |
| GODEEP_MAX_RUNTIME_REVIEW_HTML_BYTES | 16777216 | HTML response cap |

The existing report byte cap and maximum 20 combined sources apply first. Event/group
budgets apply to the complete selected scope before pagination. Exceeding a budget
returns 413, never a silently truncated result. Pagination limits displayed groups,
not summary counts; evidence sampling is separately marked. Reduce page size for an
oversized response, or select a single capture for event/group limits. Changing
bucket size affects activity groups only. These endpoints create no database rows,
audit events, queues or filesystem artifacts. They use the historical report even
if original source trace files later become unavailable.

Live emulator compatibility, isolation, reliable collection of the other streams,
repeatable test actions and externally validated ML remain pending. This milestone
improves investigation of existing evidence; it does not establish malware accuracy.
