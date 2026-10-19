# Backend architecture

Status: local intake implemented (cases, samples, bounded ZIP triage, SHA-256,
local originals and transactional case events). Authentication, revocable sessions
and case permissions are implemented. Durable jobs and a bounded archive-inventory subprocess worker are implemented.
Full malware analyzers and OS-level worker isolation remain planned. See
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
analysis workers. Queue technology and analyzer versions will be chosen after
compatibility testing. Infrastructure is not provisioned by this scaffold.
