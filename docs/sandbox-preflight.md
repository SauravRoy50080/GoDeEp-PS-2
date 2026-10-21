# Emulator preflight and bounded ADB probes

Backend 0.28.0 adds an operator-only CLI, not an APK analysis adapter:

```powershell
.\.venv\Scripts\python.exe -m godeep.sandbox.doctor
```

No profile returns structured JSON with `status: configuration_required` and exit
code 2, without opening a socket. A configured run uses an already-running ADB
server on **127.0.0.1 only**, with a dedicated non-default port (5038 by default).
It never launches/kills a server, enumerates devices, changes settings, installs
or launches APKs, transfers files, or creates a runtime capture. No new Python
package, database migration or HTTP endpoint is required.

## Operator setup

For a live check, provision Android SDK Platform Tools and an appropriate Android
Emulator/system image on the intended disposable analysis host. An emulator alone
does not establish malware containment; network/host-share controls, image
provenance and clean-state restoration remain separate unimplemented run controls.
No APK execution is authorized by a passing preflight.

Start an operator-owned dedicated ADB server in its own terminal, using your
approved SDK path (the example Windows SDK location may differ):

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" -L tcp:127.0.0.1:5038 server nodaemon
```

Bring up the intended disposable AVD through your SDK workflow and ensure its
explicit serial is available to that dedicated server. Connection/registration to
a custom server depends on the installed emulator/SDK setup and has not been
verified on this host. This CLI does not migrate devices between servers. A
read-only SDK check against the same endpoint is:

```powershell
& "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" -H 127.0.0.1 -P 5038 -s emulator-5554 get-state
```

Copy `backend/sandbox-profile.example.json` into ignored private storage, then
edit its AVD name, serial, API level and ABI to match the intended image:

```powershell
New-Item -ItemType Directory -Path backend/data/sandbox -Force
Copy-Item backend/sandbox-profile.example.json backend/data/sandbox/profile.json
.\.venv\Scripts\python.exe -m godeep.sandbox.doctor --profile backend/data/sandbox/profile.json --output backend/data/sandbox/preflight-001.json
```

The sample API 35/x86_64 profile is illustrative, not a provisioned image. Only
explicit emulator-style serials with even console ports from 5554 through 65534
are accepted. Remote hosts, arbitrary commands, unknown profile keys, duplicate
JSON keys, non-finite numbers, boolean schema versions and default port 5037 are
rejected. The profile file is limited to 16 KiB. `schema_version` must be integer 1.
API level must be 24–999; supported profile ABI values are x86_64, arm64-v8a, x86
and armeabi-v7a. AVD names use ASCII letters/digits/underscore/dot/hyphen, up to 80
characters. This is a connectivity profile, not a trusted device identity.

## What is checked

The client uses the documented ADB smart-socket protocol directly, so it does not
invoke an adb executable or inherit CLI target-selection environment variables.
It asks for server protocol version, selected-target state and shell_v2 support.
On that exact transport it issues only five fixed `getprop` probes:

| Check | Required value |
|---|---|
| ro.kernel.qemu | 1 |
| ro.boot.qemu.avd_name | Exact configured AVD name |
| sys.boot_completed | 1 |
| ro.build.version.sdk | Exact configured API level |
| ro.product.cpu.abi | Exact configured ABI |

Missing properties, offline/unauthorized targets, unsupported shell_v2, malformed
frames, nonzero remote exits or unexpected stderr stop the run with `blocked`.
Emulator versions that do not expose this AVD property may require a future
profile implementation; the check is not silently bypassed. A pass is
`preflight_checks_passed`, exit 0. Other readiness states return exit 2. Parser
usage errors also use exit 2. No pass verifies ADB server identity, binary/image
provenance, physical-device exclusion under a spoofed server, or network isolation.
Readiness is point-in-time and must not become permission to run a sample.

Each command/connection has a timeout (default 2 seconds, 0.1–10 allowed), shared
across framing and stream reads. A whole-run deadline defaults to 15 seconds
(0.1–60 allowed). Output payloads, including stderr/exit bytes, are capped at 16 KiB
per probe (64–65536 allowed). Shell replies are limited to 256 packets, including
empty packets; advertised lengths are checked before payload allocation. EOF
without a valid exit packet is a failure. Only stable error codes and small
printable observations are reported; server failure text is not echoed.

The report includes a UTC check time, CLI version 1.0.0, selected profile and exact
profile-file SHA-256, individual checks and explicit execution/isolation gaps.
`--output` creates a new UTF-8 JSON file exclusively, refusing existing output or
missing/unwritable parents. Its exact SHA-256 is printed to stderr; JSON is also
printed to stdout. These are operational records, not forensic runtime evidence
or digitally signed custody records. A failed write is not a successful export.

## Verification and current host

Tests use a real loopback TCP fake ADB peer, with fragmented replies, error/status
frames, shell packets, profile mismatches, output limits and deadlines. They do
not substitute for a live emulator test. ADB/emulator were not found on PATH or
at the standard local Android SDK paths during this step. The actual CLI smoke
check returned `configuration_required`; no real server/device was contacted.
Live emulator compatibility, provisioning, collection, restoration and isolated
APK execution remain pending. This CLI is not exposed through the public API and
does not change existing analysis jobs, scores, models, captures or reports.

Primary protocol/setup references:
[ADB guide](https://developer.android.com/tools/adb),
[ADB command reference](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/user/adb.1.md),
[smart-socket framing](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/dev/overview.md),
[ADB services](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/docs/dev/services.md).
