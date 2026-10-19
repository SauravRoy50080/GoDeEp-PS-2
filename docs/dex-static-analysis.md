# DEX identifier and network-candidate analysis — milestone 5

## Run

Use the existing authenticated upload and job workflow, with this submission:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"dex_static"}
```

The API and separate worker must both run the updated backend. No new dependency,
database migration or dataset is needed. Existing android_static and
archive_inventory adapters retain their versions and behaviour. The authenticated
GET /api/v1/analyzers catalog advertises the new adapter.

## Implemented evidence

The adapter inspects root classes.dex and standard numbered classes2.dex,
classes3.dex and subsequent multidex members. Each member receives its SHA-256.
Supported standard little-endian DEX versions are 035, 037, 038, 039 and 040.
Header sizes, identifier table bounds/indexes, string lengths and modified UTF-8
encoding are checked before identifiers are interpreted. This is a bounded
identifier-table reader, not a complete DEX validator or disassembler.

Versioned rules match exact class descriptor and method-name pairs for dynamic
loaders, reflection, process execution, native library loading, debugger checks,
SMS sending, location access and media recording. Results record method indexes
and byte offsets in the member. A method identifier may exist without a reachable
invocation. These are review leads, not observed actions, confirmed vulnerabilities,
anti-analysis verdicts or malware classifications. Method overload prototypes and
call sites are not resolved by the rules.

Network candidates include HTTP/HTTPS strings, syntactically valid domains or IPs
from their hostnames, and standalone IP literals. String indexes and byte offsets
preserve provenance. Arbitrary standalone domains are deliberately not extracted
because Java/package/resource names can resemble domains. No DNS requests, HTTP
requests, intelligence submissions or reputation checks occur. A candidate may
come from benign library code, test data or unused strings. It does not prove a
network connection or malicious destination. There is no inferred exfiltration.

## Coverage and bounds

Default caps: 16 MiB per DEX, 64 MiB total selected DEX data, 32 files, 100,000
identifiers per inspected table, 8 KiB encoded string length and 500 retained
findings per category per file. Configure backend/.env.example; values are
snapshotted when a job is submitted. Output and runtime also use the existing
worker bounds. Output exceeding the worker limit fails explicitly.

Malformed/unsupported members produce failed coverage with an error code; other
selected members remain inspectable. Overall coverage is partial if any selected
member fails or its findings are capped. No DEX produces no_dex_found rather than
a clean result. A completed job can have partial or failed member coverage.
Aggregate/member-read limits may fail the entire job before parsing.

Checksums, signatures, complete DEX structure and Android installability are not
validated. Instructions, callers, call graphs, native libraries, resources,
reflection targets, encrypted strings and embedded/nonstandard DEX payloads are
outside this adapter. No obfuscation or anti-emulation determination is supplied.
APK code is never executed. Subprocess parsing still requires future OS-level
isolation before production operation.

Future frontends must render artifact strings as escaped text. URLs can contain
private tokens; access stays case-scoped and external sharing requires case policy.

## Tests and design reference

Original synthetic table-level fixtures verify references, network candidates,
malformed bounds, unsupported format, modified UTF-8, truncation and real worker
processing of mixed multidex inputs. They are not Android-built installable apps
and do not measure malware-detection accuracy. Ground-truth APK validation and
held-out detection benchmarks remain future work.

The reader follows the [AOSP DEX format reference](https://source.android.com/docs/core/runtime/dex-format).
See [database verification](postgresql-verification.md) for recorded test results.
