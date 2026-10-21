# Passive process collection

Milestone 29 adds three connected features in backend 0.30.0: a bounded ADB
process snapshot reader, an operator-only passive sampler, and offline collection
verification with the existing runtime-capture/report handoff. No dependency,
HTTP endpoint or database migration is added.

## Run locally

Use the report-bound plan and dedicated loopback emulator profile described in
[sandbox workflow](sandbox-workflow.md) and [preflight](sandbox-preflight.md).
The plan must request the process stream. From the repository root, after installing
the backend requirements:

```powershell
.\.venv\Scripts\python.exe -m godeep.sandbox.collector collect --plan private/plan.json --profile private/profile.json --apk private/sample.apk --output-dir private/session-001 --interval 1
.\.venv\Scripts\python.exe -m godeep.sandbox.collector verify --directory private/session-001
```

The output parent must exist; the session directory must be new. Collection first
rehashes the APK/profile and performs fresh preflight. A blocked preparation
creates a blocked record without invented observations or a completed bundle.
Interrupted writes leave an incomplete directory that verification rejects.

The APK is hashed, never installed or launched. The target process must already
be running in a separately managed environment. Passing preflight establishes
neither execution authorization nor containment. Actual emulator compatibility
has not yet been tested; current integration tests use a fake loopback ADB server.

## Observations and bounds

The only process command is `ps -A -o PID,NAME`, through the selected serial's
bounded ADB shell-v2 transport. There is no arbitrary command interface. The
[upstream Toybox ps source](https://github.com/landley/toybox/blob/master/toys/posix/ps.c)
describes its field selection; this
[Chromium Android adapter](https://chromium.googlesource.com/crossbench.git/+/b0474fac434c54396bd46e9132a720b8f4f372e5/crossbench/plt/android_adb.py)
also uses this exact command. Unsupported or malformed output is rejected.

Strict UTF-8 tables require PID/NAME columns, positive unique PIDs and bounded
rows. Only the exact declared package name and its colon-prefixed subprocess
names produce events. This is unverified process-name matching: it does not prove
UID or APK ownership. Renaming, spoofing, truncation and sampling gaps limit coverage.

Process events add `action: observed` to the existing start/stop enum. Older clients
must support this additional value. Existing start/stop inputs remain unchanged.
Repeated snapshots preserve repeated observations; they do not infer start, stop,
absence, causality or PID continuity. Runtime trace schema version remains 1.

Sampling intervals are 0.1–30 seconds within the plan's 1–300 second window.
Limits are 240 snapshots, the smaller of 1,000 events or the plan event bound,
256 KiB retained raw stdout, and a 2 MiB journal. Transport output and command
and session deadlines are separately bounded. Limits stop collection explicitly.
Timestamps use a host UTC anchor and monotonic elapsed time capped to the planned
window; the journal separately records actual elapsed time, including overruns.

Process coverage is partial after any valid snapshot, otherwise not_collected.
Filesystem, network and sensitive-resource streams remain not_collected. Completed
means the sampling window finished, never complete behavioral coverage. Early
termination is partial after valid snapshots and failed otherwise. Zero matching
names is not proof of absence. Collection returns exit 0 only for completed;
blocked, partial, failed and errors return exit 2.

## Evidence and handoff

A sealed collection contains exactly six files:

- plan.json and preparation.json: exact source records.
- trace.json: normalized observed process events.
- observations.json: raw stdout in base64, hashes, statuses and event references.
- bundle.zip: existing canonical plan/preparation/trace/manifest bundle.
- receipt.json: written last, with hashes/sizes for the other five files.

Keep the whole directory private: raw process tables can contain unrelated process
names. The ZIP alone does not contain or verify the raw journal. Nothing uploads
automatically. After directory verification, submit the exact trace.json bytes
through the existing authenticated runtime-capture endpoint, then select that
capture in a combined forensic report. No new database mutation occurs in this CLI.

Offline verification rejects extra files, symlinks, hash/source mismatches and
noncanonical bundles; it replays retained raw process tables against event IDs,
names, PIDs and timestamps. Protocol failures retain a stable failure code without
partial transport bytes; output exceeding retention bounds may be discarded without
emitting derived events. A verified partial/failed record remains partial/failed.
Verify exit 0 confirms consistency within this scope, not a successful execution.
Hashes do not authenticate the device or prevent wholesale rewriting of the chain.
Isolation, image provenance, restoration and APK execution remain unverified.
