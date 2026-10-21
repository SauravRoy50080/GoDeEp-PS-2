# Backend implementation roadmap

1. Evidence foundation (local intake implemented; accounts/sessions and case permissions implemented; deployment hardening pending): cases, samples, upload validation, hashes, audit records,
   authentication, authorization, database migrations and storage.
2. Jobs and adapters (queue and archive inventory implemented; malware engines pending): bounded workers, retries, cancellation, run provenance,
   raw output retention and normalized observations.
3. Static analysis: manifest/permission/component and certificate extraction implemented;
   DEX identifier references and network-string candidates also implemented;
   decoded invoke sites and optional official signature verification are implemented; next extend normal flow to exception handling and deepen call-graph/evasion
   analysis and evaluate controlled test APKs. Resource/policy declarations, embedded-file
   classification and declared-library metadata inventory are also implemented.
4. Dynamic analysis: isolated Android environments, repeatable actions,
   filesystem/process/network observations and coverage reporting.
5. Intelligence and correlation (static grouping and permission context implemented):
   pinned local-feed exact matching with expiry and provenance implemented; next add
   provider connectors, broader cross-source correlation,
   explainable scoring and analyst review.
6. Reporting and AI (persisted forensic JSON snapshots implemented): formatted
   exports, analyst sign-off, evidence-linked explanations and investigation assistance.

At each stage evaluate false positives, category-level precision/recall and
coverage on controlled benign/malicious corpora. Do not promise accuracy before
benchmarking. No malware fixtures are included in Git.

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

Selected runtime captures can now be viewed as an evidence-linked, filtered and
paginated timeline. Clock attribution/causality remain unverified. Backend
connection review fixes OpenAPI upload documentation and local database readiness;
see [review](connection-review.md) and [timeline](runtime-timeline.md).

The library_review adapter now matches declared Maven coordinates/exact versions
to pinned offline advisory claims with expiry, withdrawal, conflict and coverage
handling. Full SCA, version ranges and packaged-code verification remain pending.
See [library advisory review](library-advisory-review.md).

The dex_graph adapter now extracts bounded method-ID invoke operands beyond
the sensitive API allowlist, retaining per-member node identity and offsets.
APK-wide budgets, partial coverage and report integration are implemented.
Resolved dispatch, entrypoint reachability and CFG/data-flow analysis remain
pending; see [invoke-operand graphs](dex-invoke-graphs.md).

Existing forensic snapshots now support authenticated, bounded, passive HTML downloads for reading and browser printing. Source hashes, coverage and collector limitations remain explicit. PDF generation and analyst sign-off remain pending; see [HTML report export](html-report-export.md).

Combined forensic snapshots now support exact canonical IP co-occurrence between
supported static candidates and imported collector events. Evidence pointers,
source hashes/coverage, unsupported-adapter status and bounded pagination remain
explicit. No DNS, causality, runtime attribution verification or scoring is added;
see [network correlation](network-correlation.md).

The dex_control_flow adapter adds bounded intraprocedural normal-flow blocks and
checked goto/conditional/switch targets, with per-method offsets, payload references,
APK-wide budgets and report support. Exception edges/handler validation, full
verification, feasible-path and entrypoint reachability remain pending. See
[normal control flow](dex-control-flow.md).

Operator-only emulator preflight now checks a selected profile through bounded
loopback ADB protocol probes, with explicit failure/coverage reporting and no
APK execution. It does not provision or verify containment. Actual emulator
compatibility and live collection remain pending; see
[sandbox preflight](sandbox-preflight.md).
