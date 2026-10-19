# Android static evidence — milestone 4

## Usage

Install from repository root: `python -m pip install -r requirements-dev.txt`.
Dependencies include pinned Androguard 4.1.4, cryptography and lxml. No Android SDK,
Java, emulator or training dataset is needed for this adapter. No migration is added.
Start the API and separate worker using [analysis jobs](analysis-jobs.md).

After authenticated APK upload, submit to
`POST /api/v1/cases/{case_id}/analyses`:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"android_static"}
```

Poll the job and retrieve its `/result` after completion. Omitting adapter keeps
archive_inventory as the default. Authenticated GET /api/v1/analyzers lists both
adapters. Owners/analysts submit jobs; authorized viewers can read results.

## Output and interpretation

Results include package/version/label declarations, SDK defaults, requested
permissions and SDK qualifiers, custom permission definitions, activities,
aliases, services, receivers, providers, intent filters, enabled/exported state
and inherited permission declarations. Resource references remain unresolved.
Requested permissions do not establish runtime grants.

Review leads cover declared debugging, cleartext traffic, backup settings,
exported components and missing required exported declarations. Each lead has a
manifest hash and logical selector. Confidence describes static interpretation,
not maliciousness or exploitability. Disabled components do not create exposure
leads; launcher activities receive separate treatment.

SDK-dependent defaults include their interpretation basis. Missing target SDK
defaults to minimum SDK; missing minimum defaults to 1. Provider export output
includes the legacy API 16-and-earlier caveat. Target 31+ components with intent
filters but no explicit exported declaration produce compatibility review leads,
not asserted exposure. Runtime reachability and installation validity are untested.

Signing output deduplicates certificates by SHA-256 and records source references,
subject/issuer, validity, public key metadata and extraction issues. Candidate v1
PKCS7 and v2/v3/v3.1 blocks are inspected. Every result explicitly marks
cryptographic verification as not_performed. Certificate presence does not prove
APK signature validity; equal subject/issuer does not prove verified self-signing.
APK content digests, signatures, lineage, platform compatibility and v4 sidecars
are not verified. Some v3.1-only blocks cannot yield certificates through the
pinned library; these produce partial coverage and a no-certificates issue.
See Android's [apksigner reference](https://developer.android.com/tools/apksigner)
for the dedicated verification tool; integration remains future work.

## Bounds and evidence

Defaults: manifest 2 MiB and 20,000 nodes; certificate members 1 MiB; signature data
8 MiB; 64 certificates. Configure backend/.env.example; job submissions snapshot
these limits. Binary XML chunks are checked before decoding. Source XML is labelled
separately; DTDs are rejected and external entities/network resolution disabled.
Invalid manifests fail explicitly. Decoder anomalies and partial signing coverage
remain visible. Input/manifest hashes and adapter/rule/tool versions are retained.

The shared worker bounds runtime and result size; exceeding output bounds fails
rather than silently dropping evidence. A subprocess is not OS-level isolation.
APK code is never executed. DEX/API/evasion analysis, resource resolution, runtime
observations, network intelligence, risk scoring and malware classification remain
future work. Completion means the adapter finished, not that an app is safe.

## Tests and accuracy

Original synthetic binary XML and certificate-bearing ZIP fixtures test manifest
semantics, inherited permissions, launcher handling, malformed input, bounds,
partial signing coverage, authenticated discovery and case-scoped worker access.
Signing fixtures deliberately lack valid APK signatures, checking that extraction
never becomes a verification claim. These fixtures establish neither Android
installability nor real-world detection accuracy. Android-built ground-truth apps
and held-out evaluation datasets are still needed. Recorded SQLite and live
PostgreSQL results appear in [verification](postgresql-verification.md).
