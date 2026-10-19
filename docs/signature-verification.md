# Official APK signature verification — milestone 8

## Run

The optional signature_verify adapter invokes official Android apksigner through
a trusted Java executable. This external-tool integration currently supports
Windows only. Other platforms return explicit unavailable/unsupported outcomes;
no external tool is launched there. APK application code is never executed.

After upload, submit the existing authenticated analysis endpoint:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"signature_verify"}
```

Poll and retrieve the result using the standard [job workflow](analysis-jobs.md).
The original snapshot hash is checked before verification, and again afterward.
Existing adapters keep their versions. android_static/static_review certificate
extraction remains explicitly unverified; signature_verify is a separate run.

## Operator setup

Install a trusted Java runtime and Android SDK Build Tools containing apksigner.jar.
Pip does not install these tools. Use official distribution sources:
[OpenJDK](https://jdk.java.net/) and [Android tools](https://developer.android.com/tools/apksigner).
No system-wide installation is required; absolute portable-tool paths are supported.
Set these locally in backend/.env (not committed), or in the worker environment:

```text
GODEEP_SIGNER_JAVA_PATH=C:/path/to/java/bin/java.exe
GODEEP_SIGNER_JAR_PATH=C:/path/to/Android/Sdk/build-tools/35.0.0/lib/apksigner.jar
GODEEP_SIGNER_JAR_SHA256=YOUR_64_CHARACTER_LOWERCASE_SHA256
```

Calculate the installed JAR digest in PowerShell:

```powershell
(Get-FileHash 'C:/path/to/apksigner.jar' -Algorithm SHA256).Hash.ToLowerInvariant()
```

Only configure binaries obtained through a trusted installation process; recording
a hash alone does not establish their publisher. The worker checks the configured
JAR digest before running it and records the actual Java executable/JAR hashes and
version output. Java runtime libraries are not individually pinned or hashed.
Paths/digest are operator settings, not accepted from job request bodies and not
stored in public job config. Operational tool updates affect subsequent attempts;
each result records the actual provenance rather than promising the same tool
across retries. Keep tool files protected from modification by untrusted users.

This development machine has a local, ignored backend/.env with portable verifier
paths only. It does not provision or change database settings. Portable tools and
downloads are outside Git; teammates must configure their own installations.

## Status and evidence

Results include signature_verification, tool provenance, exit code, bounded merged
stdout/stderr, a UTF-8 diagnostic-text digest and the input hash. Diagnostics may
contain untrusted certificate text or local file references; render as escaped
text and keep case access controls. The text digest covers stored decoded text,
not the original byte stream. It is absent for probes that fail before verification.

- verified: exit 0 with the expected success marker. Initial summary scheme flags
  are parsed before certificate-derived text. The actual verified scope uses the
  manifest minimum and the verifier's default maximum, without SDK overrides.
- verification_failed: exit 1 with the explicit DOES NOT VERIFY marker.
- tool_unavailable: missing configuration or tool files; not an invalid signature.
- provenance_mismatch: the installed JAR does not match the operator's pinned hash.
- tool_error: unexpected exit/output, process ownership failure or startup error.
- timeout/output_limit: bounded execution did not complete normally.
- unsupported_platform: this integration cannot provide process ownership there.
- input_changed_during_verification: post-run snapshot hash differs; verification
  claims and parsed scheme flags are discarded.

A completed job can report any of these outcomes. Only verified is success;
unavailable/timeout/error never mean invalid or clean. Warnings remain in tool
output and are not promoted to errors. v4 sidecars are not supplied. Verified
certificate extraction metadata is not synthesized from arbitrary output text;
raw apksigner diagnostics preserve signer information for review. Structured
signer-to-extracted-certificate binding and lineage normalization remain future work.
A valid signature does not prove a safe app, trusted publisher or installability.

## Execution bounds and process cleanup

Defaults: verification 20 seconds, each version probe at most 5 seconds, output
64 KiB per invocation, Java heap cap 256 MiB. The job's outer timeout also applies.
Timeout/output settings are snapshotted; operator paths stay worker-local. Calls
use fixed argv without a shell. Java option-injection environment variables are
removed. A Windows Job Object owns the tool with kill-on-close semantics; normal
completion, timeout, cancellation and parent death close that ownership and
terminate assigned descendants. Assignment is performed immediately after process
creation; a narrow launch-to-assignment window remains. Failed assignment kills
the direct tool and returns an operational error. This is process cleanup, not
network isolation, a total memory/disk quota or a malware sandbox. Supervision of
that launch window and production OS isolation remain future hardening.

## Verified development runtime and tests

The verification run used official Android Build Tools 35.0.0 (apksigner reports
0.9) and portable OpenJDK 21.0.2. The SDK ZIP matched its official repository SHA-1
metadata; the Java ZIP matched its published SHA-256. Actual apksigner.jar SHA-256:
00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7.
Download provenance and binaries remain outside the repository.

Tests generate original test keys, certificates and a synthetic binary-manifest
APK, sign it with the real tool, verify success and reject unsigned/modified
copies. This is a cryptographic test APK, not proof of Android installability or
real-world malware accuracy. Private test keys remain in disposable test folders.
Tests also exercise unavailable/error statuses, output parsing, timeout/output
limits, hash mismatch, parent-death cleanup and real job/result persistence.

Enable optional real-tool tests in PowerShell:

```powershell
$env:GODEEP_TEST_SIGNER_JAVA = 'C:/path/to/java.exe'
$env:GODEEP_TEST_SIGNER_JAR = 'C:/path/to/apksigner.jar'
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

Without these test variables three official-tool tests skip explicitly. Windows
process-cleanup tests run without Java. See [database verification](postgresql-verification.md)
for recorded full-suite outcomes; no training dataset is needed for this stage.
