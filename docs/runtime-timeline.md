# Runtime investigation timeline

POST `/api/v1/cases/{case_id}/samples/{sample_id}/runtime-timeline` with a bearer
session and explicit capture IDs:

```json
{
  "capture_ids": ["IMPORTED-CAPTURE-UUID"],
  "kinds": ["network", "filesystem"],
  "started_at": "2026-10-21T10:00:00Z",
  "ended_at": "2026-10-21T10:05:00Z",
  "limit": 100,
  "offset": 0
}
```

Only capture_ids is required. Select 1-10 distinct captures belonging to exactly
this case/sample. Owners, analysts and viewers can read permitted timelines;
outsiders and cross-case/sample sources cannot. It is a read-only POST with no
persisted timeline, analysis job, report, score or audit event created.

Empty kinds selects all four event kinds; otherwise use distinct process,
filesystem, network or sensitive_access values. Optional time filters require
timezones and use inclusive boundaries. Start cannot follow end. Limit is 1-200
(default 100); offset is 0-20,000. No implicit latest/all-capture selection occurs.

Every selected trace is hash/size/identity-checked and revalidated before use.
The shared trace reader also serves forensic snapshot creation, preserving the
same source checks. Missing, tampered or invalid traces return 409. Missing or
cross-scope IDs return 404. Metadata summaries are not used to reconstruct events.
Original APK bytes are not re-read for this historical observation view.

Events are sorted by collector timestamp, then capture ID, then event ID. Aware
datetimes compare by instant across offsets; source offsets remain in normalized
JSON. The total counts matching observations before pagination. Each item has
capture_id, typed event data and an evidence reference containing the exact source
artifact SHA-256 and source event UUID. Source headers retain collector, package,
environment, collection period/status and every stream's coverage.

PID identity remains local to a capture. Repeated event IDs in different captures
are retained as separate source observations. They are not merged or counted as
independent confirmation. Timestamps, package attribution and isolation remain
collector claims, with unverified clock differences. Sorting does not establish
causality or actual execution order. Empty filtered pages do not prove inactivity.

Source bytes are bounded by `GODEEP_MAX_TIMELINE_SOURCE_BYTES` (10 MiB default,
1 KiB-20 MiB supported), plus each capture's existing per-source bound. Response
bytes are bounded by `GODEEP_MAX_TIMELINE_BYTES` (1 MiB default, 1 KiB-5 MiB).
Oversized sources/responses return 413 without silently skipping selected traces.
Downloads/view responses use no-store; timeline responses also use nosniff.

No dependency or migration added; existing migration 0005 is required for capture
storage. This endpoint can feed the teammate's future timeline UI. It does not
implement a frontend, live collector, Android execution or cross-run causal graph.
