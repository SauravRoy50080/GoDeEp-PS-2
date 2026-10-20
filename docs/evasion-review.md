# Static loading and evasion-related review leads

The `evasion_review` adapter (1.0.0) combines a verified static-review snapshot,
selected resource inventory and versioned evidence grouping. Queue it through the
existing authenticated job API:

```http
POST /api/v1/cases/{case_id}/analyses
Content-Type: application/json
Authorization: Bearer YOUR_SESSION
```

```json
{"sample_id": "SAMPLE-UUID", "adapter": "evasion_review"}
```

Run the existing worker, poll the job and retrieve its `/result`. The authenticated
`GET /api/v1/analyzers` catalog lists its capabilities. No new dependencies,
operator tool configuration or database migration are required. Existing static
and threat review adapter versions and saved results remain unchanged.

`data.evasion_review.findings` contains grouped investigation leads for these
existing DEX rules:

| Category | Exact class/method allowlist |
|---|---|
| Dynamic loading | `dalvik.system.DexClassLoader.<init>`, `dalvik.system.InMemoryDexClassLoader.<init>` |
| Debugger check | `android.os.Debug.isDebuggerConnected` |
| Reflection | `java.lang.reflect.Method.invoke` |
| Native loading | `java.lang.System.loadLibrary` |

These rules match class and method names; they do not resolve Android API semantics,
arguments, dispatch or reachability. Other loading or debugging APIs can be missed.
A decoded invoke retains caller/target identity and byte offset. A method-identifier
reference remains weaker evidence; when a decoded call to that same method index
exists in the same DEX, its identifier is suppressed as duplicate evidence. Evidence
is not independently confirmed by observing it in both tables.

Header candidates from selected resource files are grouped as embedded DEX,
embedded ZIP or native ELF. Each preserves member name and member SHA-256. Header
recognition does not validate an executable payload. There is no recursive unpacking,
decryption or execution, and no inferred link between a loader API and a packaged
file. Source inventories remain in the result for detailed review.

Each lead has a deterministic input-scoped ID, subject, evidence count, retained
evidence, strongest retained evidence type, truncation status, a benign explanation
and `requires_review=true`. The existing `max_review_findings` and
`max_review_evidence` settings cap grouped output; upstream DEX/resource and overall
worker limits also apply. Findings are sorted by semantic group key. Source coverage
and output limits propagate into `partial`; `selected_rules_applied` means only
that these selected rules were applied to the inspected sources. An empty list is
not a clean verdict.

Anti-emulation, control-flow obfuscation, encrypted payload detection, reflection
target resolution, runtime loading and native behaviour are explicitly unevaluated.
This adapter provides review leads, not an evasion verdict, risk score, malware
classification or measured detection accuracy. Legitimate plugins, diagnostics,
frameworks and libraries can produce these observations.

Results use the existing case permissions, original-byte hash verification,
subprocess worker, result artifact hashing and forensic JSON report selection.
Comparison currently accepts only `static_review` and `threat_review`, so this
adapter is not accepted by the comparison endpoint. No external services receive
sample data. Training datasets are not required for this deterministic step.
