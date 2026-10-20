# Backend architecture

Status: local intake implemented (cases, samples, bounded ZIP triage, SHA-256,
local originals and transactional case events). Authentication, revocable sessions
and case permissions are implemented. Durable jobs and a bounded archive-inventory subprocess worker are implemented.
Manifest/permission/component review and certificate extraction are implemented.
DEX malware analyzers and OS-level worker isolation remain planned. See
[worker architecture](analysis-jobs.md). See [milestone guide](intake-development.md).

## Boundaries

API -> services -> domain contracts -> persistence and evidence storage.
Services schedule analysis jobs; workers invoke adapters and retain raw outputs.
Static and dynamic pipelines normalize observations before correlation and reporting.
AI consumes evidence-linked findings; it is not the authority for malware verdicts.

## Planned modules

- Cases and samples: case ownership, APK hashes, provenance and run history.
- Evidence: immutable originals, derived artifacts and integrity verification.
- Analysis: static triage, runtime observations, evasion signals and correlation.
- Integrations: independently versioned adapters for selected engines and intelligence.
- Findings: evidence references, severity, confidence, coverage and review state.
- Reports: reproducible exports with limitations and an audit trail.

## Design constraints

Keep original observations separate from derived findings and AI hypotheses.
Record analyzer/rule versions and configuration for every run.
Deduplicate shared evidence across engines; tool agreement is not always independent.
Distinguish risk, confidence, coverage and completion. Failed analysis is not clean analysis.
Isolate untrusted parsing and runtime execution; bound resources and archive expansion.
Keep runtime hosts separate from application infrastructure and investigator networks.
External submissions and intelligence publication must follow case policy.
Treat APK text and decompiled content as untrusted input to AI.

## Planned infrastructure

Python/FastAPI API, PostgreSQL metadata, object storage for artifacts, and queued
analysis workers. The database queue and adapter registry are implemented; Androguard 4.1.4 is pinned. Infrastructure is not provisioned by this scaffold.

DEX identifier tables and network-string candidates are now supported through
[dex_static](dex-static-analysis.md). Bounded invoke-site decoding is now supported by dex_calls.
Control-flow, dispatch resolution and call-graph analysis remain planned.

The static_review adapter runs static phases on one verified snapshot and groups
findings with related permission context; see [unified review](unified-static-review.md).

The signature_verify adapter adds optional official apksigner verification with
Windows process ownership and bounded diagnostics. Certificate extraction retains
its separate unverified status. See [verification integration](signature-verification.md).

Resource and declared-library observations are available through resource_inventory.
It does not resolve Android resources or infer dependency vulnerabilities.

The threat_review adapter combines static/resource evidence with pinned local
indicator-feed matching. No external intelligence submissions occur; source claims
and temporal validity remain explicit. See offline-threat-intelligence.md.

Forensic report snapshots persist selected completed results with original/source
integrity checks, case authorization, transactional creation audits and verified
JSON downloads. Migration 0004_forensic_reports is required; see forensic-reports.md.

Case-scoped comparisons of selected static/threat review runs are implemented.
They compare hash-verified recorded observations with coverage limitations; they
do not establish removed behaviour or a malware verdict. See
[sample comparison](sample-comparison.md). No migration is required for this endpoint.

The `evasion_review` adapter groups selected loading/debugger/reflection API and
embedded-file header observations with benign context, source coverage and bounds.
Anti-emulation, encrypted payloads and control-flow obfuscation remain pending.
See [evasion review](evasion-review.md); no runtime or malicious-intent claim is made.

The `risk_review` adapter now applies a versioned, uncalibrated analyst-priority
policy to static and offline-feed evidence, with category caps, source references
and coverage gaps. Dataset calibration and runtime-informed risk remain pending.
See [risk prioritization](risk-prioritization.md).

Offline priority evaluation now validates recorded results and corpus splits,
reports selective metrics with abstentions, and preserves hashes/label provenance.
No real dataset benchmark or model training has run. Category/classification
evaluation and calibration remain pending; see [dataset evaluation](dataset-evaluation.md).

A separate CSV classification research CLI now validates B/S binary datasets,
groups identical vectors before splitting and fits a training-only Bernoulli
Naive Bayes baseline. No production inference integration; extractor parity,
family/temporal validation and calibration remain pending. See
[classification baseline](classification-baseline.md).

Validation-only research selection compares Naive Bayes and a decision stump
under explicit FPR/recall constraints. Test scoring and production promotion
are excluded; fresh external evaluation and extractor parity remain required.
See [validation selection](validation-selection.md).

An offline feature compatibility audit now retains dataset order, hash provenance,
candidate manifest observations and unsupported/null features. It does not produce
model inputs or predictions; original extraction equivalence remains unverified.
See [feature compatibility](feature-compatibility.md).

Runtime capture intake now preserves bounded collector-asserted observations with
case permissions, hashes, typed events, summaries and explicit coverage. It does
not run APKs or verify isolation/attribution. Live collectors remain pending; report integration is implemented. Migration 0005 adds runtime_captures; see [runtime intake](runtime-captures.md).

Selected runtime captures are now included in version-2 forensic snapshots, alone
or alongside selected analysis jobs. Capture hashes, trace validation, sample
association and coverage are checked/preserved; collector claims are not promoted
to verified runtime execution. Analysis-only version 1 remains compatible. See
[runtime report integration](runtime-report-integration.md).
