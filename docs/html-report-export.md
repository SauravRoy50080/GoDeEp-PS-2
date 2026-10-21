# Printable forensic HTML exports

Backend version 0.25.0 adds a passive HTML presentation of an existing forensic
JSON snapshot. Create a report with selected completed jobs and/or imported
runtime captures first, then request:

`GET /api/v1/cases/{case_id}/samples/{sample_id}/reports/{report_id}/export/html`

Use the same bearer authentication as JSON downloads. Case viewers can download;
non-members and mismatched case/sample/report paths cannot. The response is an
HTML attachment, suitable for opening locally and printing through the browser.
There is no frontend dependency, server-side PDF generation, digital signature,
analyst sign-off or malware verdict.

## Contents and provenance

The export presents report identity, snapshot creation time, creator ID, case,
sample SHA-256, original-verification time, selected sources and limitations.
Analysis source summaries include adapter/version, job ID, result hash and
recorded coverage. Complete source records retain configuration, findings,
evidence offsets, graph data and partial/unavailable phases. Runtime sources
retain normalized traces, original trace hashes and collector-asserted attribution.
Unknown snapshot extension fields are preserved in a separate section.

The original JSON artifact is read through the existing bounded, hash-verified
report download service; its stored size and report/case/sample identity are also
checked. Original APKs and source artifacts are not re-read during export: their
integrity was checked when the snapshot was created. Exporting does not update
that historical verification time or independently validate runtime execution.

Response headers distinguish `X-Source-Report-SHA256` (exact persisted JSON bytes)
from `X-Export-SHA256` (exact returned HTML bytes). `X-Export-Version: 1.0.0`
identifies the renderer. With identical snapshot metadata and renderer version,
output is deterministic: no export-time timestamp or random identifier is added.
HTML is a derived presentation, not a substitute for original JSON bytes. Browser
printing changes representation; printed pages are not signed or certified.

## Bounds and passive content

Every source string is HTML-escaped. URLs are plain text, with no active links,
scripts, forms, remote fonts, images or network resources. Inline static CSS
supports wrapping and printing. CSP is delivered as both a response header and a
meta tag; frame restrictions are additionally supplied as headers. Some CSP
policies are header-only; escaped passive markup remains the primary protection
when an attachment is opened locally. Responses also use attachment disposition,
no-store, nosniff and no-referrer headers.

`GODEEP_MAX_REPORT_HTML_BYTES` defaults to 67108864 (64 MiB), configurable from
1024 through 134217728 bytes. Escaping can enlarge source JSON. The renderer
counts UTF-8 output bytes and returns 413 if the complete presentation exceeds
the budget; it never silently truncates evidence. Existing JSON source limits
still apply. Rendering is in memory, so deployment worker/memory limits remain
necessary. Invalid or tampered snapshots return 409. Existing v1 analysis-only
and v2 runtime/combined snapshots are supported. No migration, package, database
write or additional stored artifact is required.

For a useful browser printout, choose A4/Letter and review page breaks before
sharing. Long source records can span pages. Automated checks cover escaping,
determinism, byte bounds, provenance headers, tampering, permissions and both
snapshot schemas; browser/PDF pagination is not certified.
