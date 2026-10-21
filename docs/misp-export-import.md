# Offline MISP export handoff

Backend 0.34.0 adds ten connected capabilities: bounded offline input, identity
validation, domain/URL mapping, IP/composites, file hashes, certificate fingerprints,
eligibility filters, provenance/expiry, replay-verifiable packages and worker/report
handoff. No dependency, endpoint, migration or frontend change is required.

## Convert and verify

Keep exports in an ignored private data folder. From the repository root:

```powershell
.\.venv\Scripts\python.exe -m godeep.integrations.intelligence.misp_export convert --source backend/data/private/misp-export.json --output-dir backend/data/private/misp-import-001 --feed-id local-misp --source-name "Operator-reviewed export" --source-url https://misp.example.org
.\.venv\Scripts\python.exe -m godeep.integrations.intelligence.misp_export verify --directory backend/data/private/misp-import-001
```

The parent must exist and output directory must be new. Conversion finishes before
creating it; source.json and feed.json are written exclusively, receipt.json last.
Existing files are never overwritten. Interrupted writes leave incomplete packages
that verification rejects. Nothing is uploaded, published or installed as active
configuration. CLI output contains status/counts/feed hash, without indicator values.
Conversion returns 0 for emitted indicators, 2 for failure or no_eligible_indicators.
Verification returns 0 for consistent packages, including empty ones; it does not
establish current freshness, trusted origin or maliciousness.

## Supported subset

Accepted envelopes are exactly an object with Event, or an object with response
containing Event wrappers. Only direct Attribute and Object[*].Attribute arrays are
traversed. This is not a full MISP validator or synchronization client. References:
[MISP core format](https://www.misp-standard.org/rfc/misp-standard-core.html),
[MISP API documentation](https://www.misp-project.org/openapi/).

| MISP type | GoDeEp indicator |
|---|---|
| domain, hostname | Canonical exact domain |
| url | Canonical HTTP(S) URL |
| ip-src, ip-dst | Canonical exact IP |
| domain\|ip | Separate domain and IP candidates |
| ip-src\|port, ip-dst\|port | IP only, after port validation |
| hostname\|port | Domain only, after port validation |
| sha256, filename\|sha256 | Hash compared against original APK bytes |
| x509-fingerprint-sha256 | Certificate SHA256 fingerprint |

Existing canonicalization applies. No DNS/contact/routing or parent-domain inference
occurs. Scoped IPs/CIDRs are excluded. Composites require exactly two nonempty parts;
ports must be 1-65535. Ports/filenames are not matched. A domain-IP pair is not DNS
evidence; generic hashes do not imply original APKs. Fingerprints do not verify trust.

Duplicate JSON keys, nonfinite numbers, duplicate normalized UUIDs, malformed event
wrappers/arrays/required fields and future event timestamps reject conversion. Invalid
attributes become counted diagnostics with stable codes and source pointers. Values
are bounded to 4096 characters before existing feed limits. Timestamps require Unix
second strings and represent modification metadata, not observed application behavior.
Booleans accept JSON booleans, numeric 0/1 or strings "0"/"1"; "true" is not accepted.

Events must be published, not deleted and not disable_correlation. Deleted objects
exclude their attributes. Attributes require to_ids and must not be deleted or
disable_correlation. Missing optional flags default false; missing required fields
do not create eligible records. All traversed attributes count toward limits.
Related events, proposals, sightings, tags, galaxies and relationships are not modeled.
Detection/publication flags never become malware classifications.

## Policy and provenance

Defaults: classification unknown, confidence unknown, validity 24 hours and maximum
attribute age 30 days. Optional flags are --published-at (aware ISO timestamp),
--valid-hours (1-168), --max-attribute-age-days (1-365), --classification
(unknown/benign/suspicious/malicious) and --confidence (unknown/low/medium/high).
Publication defaults to host UTC. Expiry is the earlier of feed expiry and modification
time plus maximum age. Stale/future attributes are excluded, preventing indefinite
renewal under the same age policy. Existing loaders separately enforce feed freshness.

Labels/confidence are operator-wide assertions, not inferred MISP verdicts. Source
names explicitly label operator classification and modification-time semantics.
Non-unknown labels can affect existing uncalibrated risk prioritization; no scoring
policy or model changes here. Unknown matches do not earn positive intelligence points.

Retain all three private files: exact source.json, deterministic Feed-schema-1 feed.json,
and receipt.json with policy, hashes/sizes, counts, exclusions and per-indicator UUIDs,
source type and pointer. IDs derive from converter version, event/attribute UUIDs,
mapped kind and value. The receipt maps matches back to raw source. References use the
operator base URL, which must be HTTP(S) without userinfo/query/fragment; nothing fetches
it. Sharing metadata remains in raw source, but distribution rules are not enforced.

Verification requires exactly three regular nonsymlink files and a nonsymlink root,
bounded reads, and byte-for-byte replay of feed and receipt. Changed bytes/summaries
or extra files fail. Identical source/policy reproduce outputs under the same
implementation. Hashes do not authenticate origin or prevent wholesale rewriting.

## Worker handoff

After verification, configure the existing settings with an absolute path and the
printed exact feed SHA256; restart the API/worker as appropriate:

```text
GODEEP_INTEL_FEED_PATH=ABSOLUTE_PATH_TO_PACKAGE/feed.json
GODEEP_INTEL_FEED_SHA256=EXACT_FEED_SHA256
```

Queue threat_review or risk_review. Existing exact matching, expiry/conflict and byte
rules apply. Results retain feed hash/source name and matched IDs. Select the job in
a forensic report and reference its intelligence through analyst reviews. Join feed
hash and matched IDs to the retained receipt for MISP provenance. The loader checks
the feed pin but does not automatically verify/store the package. Configuration is
read at worker execution time as before; this command does not install or queue it.

Limits: source 8 MiB, 500 events, 2000 objects, 10000 traversed attributes and 10000
emitted indicators including composites, feed 2 MiB, receipt 4 MiB. Counts are checked
before flattening/expansion. Hard limits abort without publishing truncated feeds.
Coverage always remains partial_misp_format_subset. Existing loader limits may be lower.

Live synchronization/authentication, multi-feed aggregation and richer sharing/taxonomy
translation remain pending. This does not execute APKs, collect runtime activity,
train models or establish detection accuracy. Sandbox isolation, formal sign-off
and externally validated ML remain separate work.
