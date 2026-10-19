# PS-02: repository research and architecture reference

Reviewed: 19 October 2026. Scope: public repository READMEs, layouts, documented interfaces, and Quark documentation. No tools were installed or benchmarked; this is an architecture review, not a full source audit. Capabilities below are documented claims, not independently measured accuracy. Recheck pinned releases before implementation.

## Project intent

Build an advanced Android security and forensic platform for investigators. Priorities: evidence provenance, measured detection quality, static/runtime correlation, explainable scoring, reproducibility, batch investigation, and grounded AI assistance.

## Repository patterns

| Repository | Documented purpose and strength | Pattern to carry forward |
|---|---|---|
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Broad mobile static/dynamic assessment with REST and CLI automation. | Adapter-based integration into analysis jobs; unified investigation workflow. |
| [Sandroid core](https://github.com/fkie-cad/Sandroid_core) | Android sandbox, forensic artifacts, runtime monitoring, companion instrumentation, and a ground-truth APK. | Before/after artifact capture, repeatable actions, noise control, calibration fixtures. |
| [Dexray Insight](https://github.com/fkie-cad/Sandroid_Dexray-Insight) | Modular APK static analysis, external reputation, APKiD/unpacking integration, library checks, and separate confirmed findings/review leads. | Typed module outputs; preserve the distinction between findings and hypotheses. |
| [Androguard](https://github.com/androguard/androguard) | Programmatic APK/DEX analysis and reverse-engineering interfaces. Repository and published-package versions differ in documented setup. | Method-level evidence, references and a version-pinned parser adapter. |
| [Quark](https://github.com/ev-flow/quark-engine) and [docs](https://quark-engine.readthedocs.io/en/latest/) | Rule-driven Android bytecode analysis and behaviour reports. | Explainable, versioned behaviour rules; validate rather than adopt scores as probabilities. |
| [APKiD](https://github.com/rednaga/APKiD) | Identifies compilers, packers, obfuscators and protection-related signatures; JSON interface. | Early triage signals that select deeper analysis, without treating protection as maliciousness. |
| [DroidLysis](https://github.com/cryptax/droidlysis) | Reverse-engineering preparation, configurable patterns and artifact organization; known SDK code is excluded by default. | Evidence locations and SDK attribution; explicitly expose excluded coverage. |
| [AndroPyTool](https://github.com/alexMyG/AndroPyTool) | Batch orchestration of static/dynamic feature extraction; JSON/CSV and database output. | Stage checkpoints and reproducible feature datasets; validate its older dependencies separately. |
| [MISP](https://github.com/MISP/MISP) | Structured intelligence, indicator correlation, warning lists and controlled sharing. | Provenance-aware enrichment, scoped correlation and investigator-controlled publication. |

## Proposed architecture decisions (our synthesis)

1. Maintain our own case/evidence model and orchestrator. Integrate selected engines behind replaceable adapters; do not install all nine as a single dependency stack.
2. Preserve original APKs and raw outputs in content-addressed storage. Each run records SHA-256, analyzer version/commit, rule digest, configuration, timestamps and environment identity.
3. Normalize observations into a common schema: sample_id, run_id, analyzer, rule_id, evidence_id, location, observation_type, severity, confidence, coverage and limitations. Schema details remain provisional until implementation.
4. Deduplicate evidence across wrappers and shared dependencies. Multiple reports of the same permission or API call are not independent confirmation.
5. Keep risk, confidence, coverage and analysis completion separate. No observed behaviour does not imply safety. A rule match percentage is not a calibrated malware probability.
6. Represent evidence relationships explicitly: permission -> code location -> executed API -> captured destination -> artifact. Distinguish co-occurrence, temporal association and demonstrated data flow. Infer causality only when supported.
7. Separate application code from SDK/library evidence without hiding library risk. Require reliable component/version identification before asserting vulnerability applicability.
8. Isolate static parsing as well as execution. Use resource limits, bounded archive expansion, restricted networking and disposable workers; run dynamic Android environments on dedicated isolated hosts.
9. Track failed hooks, unsupported Android/API/ABI combinations, encrypted traffic visibility and untriggered paths as coverage gaps. Compare original and instrumented runs where instrumentation may alter behaviour.
10. Use ground-truth apps with known file, database, network and sensitive API actions. Evaluate precision/recall per category, false positives on benign apps, family-separated and time-separated samples, and score calibration. External antivirus consensus is supporting evidence, not unquestioned ground truth.
11. AI explains evidence and proposes review tasks. Every factual report claim links to evidence; unsupported conclusions remain hypotheses. Treat APK strings, metadata and decompiled text as untrusted input, including potential prompt injection.
12. Cache intelligence with source and retrieval time. Respect case boundaries and explicit publication policy. An IoC match or shared certificate supports investigation, not automatic actor attribution.

## Integration order

- Foundation: evidence store, case/run API, task queue, adapter contract and evaluation fixtures.
- Static baseline: benchmark MobSF adapter plus a pinned Androguard adapter and APKiD. Avoid duplicate parsing where practical.
- Behaviour rules: evaluate Quark; use Dexray as a comparative reference and candidate specialist adapter.
- Runtime: prototype one Sandroid-backed isolated worker, then assess modern Android/ABI coverage and repeatability before scaling.
- Intelligence: MISP adapter with local caching and controlled sharing.
- DroidLysis and AndroPyTool: architecture references and optional comparison tools; runtime adoption depends on incremental value and compatibility testing.

## Required follow-up before selecting dependencies

Pin actual commits/releases; inspect adapter-facing implementation and output schemas; test on controlled APK fixtures; review transitive dependencies and licenses for the intended distribution. Service separation alone does not establish license compatibility. Specifically verify current Androguard repository/package compatibility and the Dexray README warning that its Docker container is old and untested.

## Outstanding user context

Hardware, deployment environment, deadline, intended operational use and project repository are not yet supplied. No malware samples have been downloaded or executed. The initial backend scaffold has been created; analysis engines are not implemented.
