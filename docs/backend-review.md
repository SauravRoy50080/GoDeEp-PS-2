# Backend review — 20 October 2026

Reviewed intake/storage boundaries, authentication and sessions, case authorization,
job claims/cancellation/retries, artifact integrity, manifest/DEX parsing, grouped
findings, signature verification and worker process ownership. Repository main
matched origin/main and was clean before work. No AGENTS.md instructions were found.

Found and fixed: a zero-length code_item for a concrete DEX method could count as
a decoded body and give complete call coverage. It now produces partial coverage
with dex_code_header_invalid. Added a regression fixture. dex_calls and static_review
patch versions are 1.0.1; component provenance now uses the actual calls adapter
version. Historical completed results are retained. Old queued/retried versions
are not silently rerun as new versions: unsupported_adapter_version is explicit;
submit a fresh analysis for current versions.

Baseline after the coverage correction: SQLite 113 passed, six PostgreSQL-only
checks skipped, including enabled real Java/apksigner tests. One existing Starlette
TestClient deprecation warning remains. Lint and dependency consistency passed.
Final combined SQLite/live PostgreSQL results are recorded in postgresql-verification.md.

This is source review and regression verification, not a proof that every possible
input is correct. Earlier functional scope remains intact; full DEX/resource
validation, production isolation, tamper-evident audit, deployment hardening and
malware-detection benchmarks still require further work. Tool/runtime files and
private local configuration remain outside Git.
