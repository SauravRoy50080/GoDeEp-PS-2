# Forensic reports with imported runtime evidence

Reports now accept explicitly selected completed analysis jobs, imported runtime
captures, or both for the same registered sample. Existing analysis-only report
requests and persisted version-1 downloads remain compatible. No new migration
or dependency is added. Runtime imports require the existing migration
`0005_runtime_captures`; apply it if you have not completed the previous step.

## Request

Use the existing authenticated endpoint:
`POST /api/v1/cases/{case_id}/samples/{sample_id}/reports`

```json
{
  "job_ids": ["COMPLETED-JOB-UUID"],
  "capture_ids": ["IMPORTED-CAPTURE-UUID"]
}
```

Either list can be omitted or empty, but select at least one and at most twenty
total sources. IDs must be distinct within each list. Sources must belong to the
same case and registered sample; a separate registration with the same APK hash
is still a different sample. Source selection is explicit and sorted. No implicit
latest selection, rerun, event collection or external query occurs.

Owners/analysts create reports; permitted viewers can read/download them. Existing
case and report permissions apply. Capture-only reports have an empty analyses
list and source_job_ids. Public metadata still exposes source job IDs; capture IDs
are recorded inside the snapshot selection and report-created audit details.

## Version and source semantics

Analysis-only requests produce schema 1, preserving the previous document shape.
Any runtime capture produces schema 2. The response metadata schema_version
identifies the persisted artifact format. Existing version-1 snapshots are not
rewritten and do not need conversion.

Version 2 adds `selection.source_capture_ids`, `selection.runtime_capture_count`
and a `runtime_captures` array. Each entry records capture ID, source artifact
SHA-256 and byte size, importing user/time, source_run_id, explicit collector
attribution/isolation caveats, and a validated normalized copy of the trace.

At creation, the original APK is hash/size-checked. Every selected capture is read
under its size bound, rehashed, length-checked and validated again with the same
strict trace decoder used at import. Trace input hash must match the sample and
stored capture identity; source_run_id must match metadata. Missing/tampered or
invalid sources fail with 409; out-of-case/sample/missing sources return 404.
Bounds apply to combined raw source bytes and final report bytes (10 MiB default).
Oversized reports return 413; invalid selections return 422.

Source hashes refer to exact original capture bytes. Embedded traces use
`validated_normalized_trace_v1`: datetime/IP/UUID representations may normalize,
and JSON whitespace/order changes during report serialization. Hash the original
capture bytes to verify the source, not a reserialized embedded data object.
Untrusted database summaries are not used to reconstruct observations; the source
trace is revalidated and copied. Report hashes independently protect stored report
bytes relative to metadata.

Collector attribution, package identity, timestamps and isolation remain claims.
Completed/partial/failed status and each stream's coverage survive unchanged in
meaning. No event-count score, clean verdict, API-call execution confirmation,
static-to-runtime causal linkage or independent confirmation is inferred.
Static findings and runtime observations remain separate source sections.

## Snapshot lifetime and remaining work

Reports preserve the selected evidence at creation. Downloads verify report hash
and size without requiring sources to remain available; source deletion/tampering
therefore does not change an existing valid snapshot. A newly requested snapshot
will check sources again and fail if they are unavailable. Transaction rollback
cleans newly created report files/audit entries; existing artifacts are not replaced.
There is still no report update/delete or analyst-signoff API.

Live collectors/emulators, verified sandbox isolation, event correlation, PCAP
handling, examiner signatures and formatted PDF/HTML exports remain pending.
No new model training or thresholds changed in this step. Full-platform progress
is approximately 55% of planned backend scope, not a measured accuracy statistic.
