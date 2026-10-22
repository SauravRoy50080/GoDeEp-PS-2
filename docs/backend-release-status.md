# Backend release 0.35.0

The backend supports evidence intake, case permissions, queued static analysis,
correlation, forensic reports, analyst reviews, and portable evidence packages.
It is not yet a fully validated production Android malware analysis platform.

Verification on 22 October 2026: the full suite passed **666 tests** against
disposable PostgreSQL 17.11 databases, including configured official signature
tools. SQLite recorded 658 passed, six PostgreSQL-only skips and two expired-job
setup failures; all eleven release-control tests passed on a separate rerun.
Focused worker/release/audit checks passed 26 tests. Lint, formatting and
dependency checks passed. See [verification history](postgresql-verification.md).

| Requirement | Current implementation | Remaining validation |
| --- | --- | --- |
| Static, manifest and resources | Fourteen registered static adapters, bounded parsers, evidence references | Representative real APK corpus and independent accuracy evaluation |
| Dynamic behaviour | Imported runtime captures, process sampling, workflow preparation | Isolated Android lab, execution containment, filesystem/API/network collectors |
| Permissions, APIs and evasion | Static indicators and explicit coverage limitations | Ground truth and runtime confirmation; indicators are not malware verdicts |
| Network, certificates, libraries | Extraction, signing verification integration, pinned offline feeds | Feed maintenance, platform-specific tool deployment and representative samples |
| Threat intelligence and risk | Offline correlation and explainable heuristic prioritisation | Operational feeds and calibrated risk evaluation |
| AI assistance | Offline CSV research and corpus auditing | Original APKs, extractor parity, leakage-resistant evaluation and calibration |
| Investigation interface | Authenticated APIs, comparisons, report and review exports | Frontend implementation and user acceptance testing |
| Forensic evidence | Immutable source hashes, audit events, deterministic packages and offline signatures | Institutional procedures, identity verification and trusted timestamps |

New release controls include trusted hosts, exact CORS origins, bounded JSON
requests, production documentation defaults, schema readiness, and authenticated
capability reporting. Readiness checks the metadata database and migration head
only; it does not establish worker, storage, sandbox or model readiness.

Container deployment and GitHub Actions definitions are supplied but have not
been executed in Docker or GitHub in this environment. Local test results must
not be described as a successful hosted CI run. No production accuracy percentage
has been established. CSV datasets alone cannot establish APK feature parity.

The supplied archive contains CSVs rather than APKs. Its audit records invalid
values, conflicting labels and schema differences without repairing or training
on them. See [corpus audit](corpus-audit.md).

Before production use: validate deployment and restore backups; provision an
isolated Android lab; supply a labeled APK corpus with documented extraction;
measure false positives and false negatives; establish operational signing and
review procedures. These are completion gates, not optional accuracy claims.

See [deployment](deployment.md) and [evidence packages](evidence-package.md).
