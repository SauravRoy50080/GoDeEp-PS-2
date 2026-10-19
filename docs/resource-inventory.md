# Resource and declared-library inventory - milestone 9

## Run

Submit through the existing authenticated case analysis endpoint:

```json
{"sample_id":"UPLOADED_SAMPLE_UUID","adapter":"resource_inventory"}
```

Use the updated API and separate worker; poll status and read /result using
[analysis jobs](analysis-jobs.md). No new dependency, migration, Android SDK or
training dataset is required. Individual earlier adapters retain their contracts;
dex_calls/static_review are now patch version 1.0.1 after the review correction.
This adapter is separate from static_review; it does not alter historical results.

## Selected evidence

The adapter selects assets/, res/raw/, res/xml/ and qualified res/xml-* paths,
lib/ .so entries, META-INF/maven/*/*/pom.properties and META-INF/ .version markers.
Every successfully read member receives its original name, size and SHA-256.
Files are read in memory under bounds; none is extracted to a member-supplied path.

- Embedded DEX/ZIP magic is recognized even under misleading asset suffixes.
  These are candidate formats, not verified payloads or maliciousness verdicts.
- ELF candidates expose bounded header bitness, endianness and machine ID. The
  observed ABI-directory label is retained without proving ABI compatibility,
  ELF validity, library identity, loading or vulnerable functions.
- Maven properties expose declared groupId/artifactId/version, source hash and
  whether path identity agrees. Conflicting path identity produces partial coverage.
- Version files retain their filename marker and declared version. This does not
  establish which code is present or that the marker's producer is truthful.
- Source and compiled binary XML expose network-security-config declarations with
  logical selectors, including domains, trust-anchor sources and cleartext flags.
  References from the manifest, resource qualifiers, inheritance, defaults and
  runtime policy are not resolved; an observed policy may be unused.
- URL literals yield syntactic URL/domain/IP candidates, not observed destinations.
  UTF-8 text candidates have byte offsets at the URL start; decoded XML candidates
  have logical selectors rather than invented binary offsets. No DNS/HTTP calls occur.

All library candidates say identity_verified=false and vulnerability_status=not_queried.
This is not a complete SBOM, library fingerprinting engine or CVE assessment. It
must not label a dependency vulnerable based on a filename or coordinate alone.

Maven properties support a conservative ASCII subset with explicit '=' or ':'
assignments. Escapes, continuations, non-ASCII, duplicate keys, unresolved versions
and missing/invalid identity fields produce an explicit unsupported/invalid state.
They are not silently guessed. Full Java Properties semantics remain future work.

## Bounds and coverage

Defaults: 128 retained selected files, 1 MiB per member, 16 MiB total declared
attempted data, 2,000 XML nodes and 500 retained network candidates. Per-XML URL
and declaration limits also apply. At most 100 skipped-member details are retained;
skipped_count and skipped_records_truncated expose omitted skip records. Limits
are snapshotted at submission and configurable through backend/.env.example.
Oversized or unreadable members, parse failures, decoder anomalies, identity
conflicts and capped candidates result in partial coverage. No selected files
yields no_selected_members. selected_members_inspected means this limited profile
finished, not a complete resource or malware assessment. Output exceeding the
shared result-size bound fails the job rather than silently dropping evidence.

Source XML disables entity/network resolution and rejects DTDs. Binary XML receives
chunk/string-pool checks before decoding. resources.arsc is not resolved. Unsupported
binary data remains hashed/classified; ZIPs are not recursively opened and APK code
is never executed. Large native libraries may be skipped by the configured member
limit. Encoded/encrypted strings, arbitrary standalone domains and files outside
selected paths can be missed. A subprocess still needs production OS isolation.

## Verification and sources

Tests exercise declared coordinates, duplicate/unsupported properties, path
conflicts, version markers, text and binary XML URL provenance, policy selectors,
DTD rejection, file/member/output limits, embedded magic, ELF headers and a real
case-scoped worker/result workflow. Fixtures are original and synthetic, not a
malware-detection benchmark. See [database verification](postgresql-verification.md).

References: [Maven Archiver metadata](https://maven.apache.org/shared-archives/maven-archiver-3.2.0/)
and [Android network security configuration](https://developer.android.com/privacy-and-security/security-config).
