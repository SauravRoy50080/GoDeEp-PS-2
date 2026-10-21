# Three-step sandbox collection handoff

Backend 0.29.0 adds an operator CLI for a run plan, a preflight-linked preparation,
and an exact-byte evidence bundle. It connects existing forensic snapshots,
emulator preflight, imported runtime traces and the existing case API. It does
**not** implement a live collector, install/launch APKs, restore snapshots, enforce
network isolation or authorize execution. A live emulator is still required to
exercise preparation outside protocol fixtures.

Use private files under ignored `backend/data/sandbox/`. Download an existing
forensic JSON snapshot that contains static_review 1.0.1 or threat_review 1.0.0,
and retain the exact original APK and emulator profile used for that sample.

## 1. Create a bounded plan

```powershell
.\.venv\Scripts\python.exe -m godeep.sandbox.workflow plan --report backend/data/sandbox/report.json --profile backend/data/sandbox/profile.json --duration 60 --max-events 2000 --output backend/data/sandbox/plan-001.json
```

The plan records a new run UUID, case/sample/report IDs, exact report and profile
SHA-256, APK hash/size, the static manifest's declared package, normalized emulator
profile and requested stream/event/duration limits. Supported static sources must
agree on one package and match the report's input identity. Other adapters do not
supply a package for this step. A plan is metadata, not an execution script or
malware verdict. Report files are operator-provided records; this CLI does not
independently authenticate their origin/signature or consult the case database.

Plan creation parses bounded JSON, not APK code. The package name is taken from
static report metadata and is not a verified runtime attribution. Duration is
1–300 seconds and event count 1–2000. Requested streams use the existing process,
filesystem, network and sensitive_access vocabulary; stream lists must be unique.
The default requests all four. `execution_authorization` is always `not_granted`.

## 2. Prepare against the exact input/profile

```powershell
.\.venv\Scripts\python.exe -m godeep.sandbox.workflow prepare --plan backend/data/sandbox/plan-001.json --profile backend/data/sandbox/profile.json --apk backend/data/sandbox/original.apk --output backend/data/sandbox/preparation-001.json
```

Preparation rejects future/over-24-hour plans, changed profile bytes/values and
changed APK hashes/sizes before contacting ADB. It then performs the existing
bounded, exact-target preflight. The record retains the exact plan hash, input
and profile identities, all probe results and a completion time. Its state is
`blocked` or `preflight_passed_execution_not_authorized`. Blocked preparations
are preserved as operational records with exit code 2; a passing preflight uses
exit 0. All APK reads are hash-only, capped by the planned size (at most 200 MiB).
No sample is transferred or executed. File read byte limits do not impose a
wall-clock timeout on operator-selected local files.

See [preflight setup](sandbox-preflight.md) for the dedicated loopback server.
The preparation does not verify containment, peer identity, image provenance or
future input immutability. A later execution orchestrator must recheck inputs and
control the run environment. A passing preparation is not execution permission.

## 3. Package and verify externally collected evidence

A separate collector must produce the existing RuntimeTrace v1 JSON, with the
plan's APK hash, declared package and run UUID as source_run_id. This code does
not invent events or generate a capture when none was collected.

```powershell
.\.venv\Scripts\python.exe -m godeep.sandbox.workflow bundle --plan backend/data/sandbox/plan-001.json --preparation backend/data/sandbox/preparation-001.json --trace backend/data/sandbox/trace.json --output backend/data/sandbox/run-001.zip
.\.venv\Scripts\python.exe -m godeep.sandbox.workflow verify --bundle backend/data/sandbox/run-001.zip --trace-output backend/data/sandbox/verified-trace-001.json
```

Bundling checks source identities, preparation status/observations/profile and
preflight timestamp consistency. The preflight must fall after plan creation and
finish within the configured total timeout plus five seconds of its start. The
collector's asserted start must be within ten minutes after preparation. Its
asserted interval/event count must fit the plan, and unrequested streams must be
not_collected. Trace input/package/run/environment must match the plan. Failed or
partial captures remain failed/partial, with their original coverage, if otherwise
consistent. These are **checks of recorded claims**, not enforcement or verification
of what an external collector actually did. Future trace ends over five minutes
ahead of the packaging host's clock are rejected; clock attribution is unverified.

The canonical ZIP contains exactly plan.json, preparation.json, trace.json and
manifest.json. Original source bytes, including trace formatting, are preserved.
The manifest binds their sizes/hashes, case/sample/run identity, collection status
and coverage, with collector_asserted_not_verified attribution and not_verified
isolation. Export has fixed member order/timestamps/metadata and no compression;
identical source bytes produce identical bundles. Verification rejects changed
files/metadata, unknown/duplicate member names, unsupported compression, noncanonical
headers, preambles/trailing bytes and inconsistent source records. It reads entries
in memory and never extracts archive-supplied paths.

Limits are 10 MiB for report input, 16 KiB for profile input, 64 KiB each for plan
and preparation, 2 MiB for trace and 3 MiB for bundle input. JSON rejects duplicate
keys, non-finite numbers and non-integer schema versions. Output files are created
exclusively; existing files are never overwritten and parent directories must
already exist. Success prints exact artifact SHA-256 and byte size. Verification
also prints the bundle hash and, optionally, writes the unchanged trace to a new
explicit path. Hashes are not digital signatures or tamper-proof custody: someone
who can rewrite all records can recompute the entire chain.

Import verified-trace-001.json through the existing authenticated runtime-capture
endpoint for the manifest's case/sample IDs. The API independently checks access,
original evidence and trace identity. It does not receive or enforce the whole
bundle's plan/preparation policy. Preserve the bundle privately alongside the
API trace and its source hash; include the imported capture in a forensic report
using the existing capture_ids selection. No upload is performed automatically.

The integrated test uses a real API-created static report and original sample,
loopback fake ADB, bundle verification, exact-byte capture upload and a combined
forensic report. This proves implemented backend connections, not live collection
or isolation. No new package, database migration, score or model change is needed.
