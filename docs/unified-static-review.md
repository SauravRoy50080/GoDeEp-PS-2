# Unified static review — milestone 7

## Run

After authenticated APK upload, submit to the existing case analyses endpoint:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"static_review"}
```

Run the updated API and separate worker. Poll status and retrieve /result as in
[analysis jobs](analysis-jobs.md). No migration, dependency or dataset is added.
Individual adapters retain their versions. The authenticated analyzer catalog
advertises static_review alongside the four existing adapters.

## Combined output

A single original-byte verification and bounded snapshot feeds manifest decoding,
certificate extraction and DEX invoke analysis. Results retain raw observations
under manifest, signing and dex. The review section adds:

- Deterministic finding IDs based on input SHA-256, correlation version and group key.
- Manifest review leads with selectors and manifest hashes.
- API evidence grouped by rule, class descriptor and method name, across overloads
  and DEX members. Call evidence retains full caller/target details and offsets.
- Related permission declarations with their raw SDK qualifiers and manifest hash.
- Network-string candidates grouped by exact kind and value, with source locations.
- Summary counts, analyst-review requirements, evidence caps and correlation coverage.

A corresponding method identifier is suppressed when a retained decoded call
already represents that method in the same DEX member. Exact repeated evidence
is deduplicated. Separate member locations may remain as separate references;
independent confirmation is explicitly not established. More tools, duplicate
code or more references never increase a score; scoring is not implemented.
Evidence state distinguishes declarations, identifier references and decoded calls.
Confidence refers only to the underlying static observation. It does not measure
exploitability, malware probability, execution or accuracy of permission inference.

## Permission context

Initial mapping covers SMS-send, location-access and media-recording review rules.
Related declarations are displayed as contextual co-occurrence, not as runtime
grants, data flow or confirmed permission enforcement. Location has alternative
coarse/fine declarations; media recording depends on capture configuration. SMS
privileges and Android behaviour can vary by API/role/platform context.

States are related_declaration_observed, no_related_declaration_observed,
manifest_unavailable and not_mapped. An absent declaration is never labelled a
confirmed vulnerability. maxSdkVersion and specialized permission element names
remain visible; device applicability and resource-based names are unresolved.

Mapping references: [SmsManager](https://developer.android.com/reference/android/telephony/SmsManager),
[LocationManager](https://developer.android.com/reference/android/location/LocationManager),
[MediaRecorder](https://developer.android.com/reference/android/media/MediaRecorder).

## Coverage and limits

Coverage reports manifest, signing, DEX and correlation separately, plus explicit
not-analyzed states for dynamic/resource/intelligence/scoring work. A malformed
manifest does not hide available DEX evidence; malformed DEX members do not hide
manifest observations. Parse-limit phase failures are retained with error codes.
Original integrity/archive validation failures still fail the job. Unexpected
parser failures may fail the job; only documented adapter failures are retained.
An empty finding list or completed job is not a clean verdict.

Default review caps are 500 finding groups, 500 network-candidate groups and 50
retained evidence references per group. Unique evidence_count and evidence_truncated
remain visible when references are capped; correlation coverage becomes partial.
Finding IDs identify a group for this sample and rule version, not a complete
cross-version finding history. Group counts describe retained output, not all
possible findings. Original phase observations are retained subject to their own
limits. Overall output exceeding worker bounds fails explicitly rather than
silently dropping the raw evidence.

Resource resolution, full DEX validation, reachability, runtime behaviour,
signature verification, threat reputation, library vulnerability analysis, risk
scoring, analyst-state persistence and forensic report export remain future work.
A subprocess is not OS-level isolation. No APK code or external traffic is executed.

## Validation

Synthetic fixtures verify permission qualifiers, distinct missing/unavailable
manifest states, identifier/call deduplication, stable IDs, evidence/finding limits,
network candidate grouping and real worker results with broken manifests or DEX.
Cross-case result access remains denied. These establish functional behaviour,
not real-world malware detection accuracy. See [verification](postgresql-verification.md).
