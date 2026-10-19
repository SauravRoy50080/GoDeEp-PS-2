# Live PostgreSQL verification

## Verified result — 19 October 2026

- PostgreSQL 17.11, Windows x86-64, MSVC 19.44.35229.
- Python 3.12.10, SQLAlchemy 2.0.55, psycopg 3.3.6 and Alembic 1.20.0.
- Full suite with PostgreSQL enabled: **40 passed** in 36.46 seconds.
- SQLite regression suite: **36 passed, 4 PostgreSQL-only tests skipped**.
- Both runs report one dependency deprecation warning from Starlette's HTTPX
  TestClient integration; no application test failures.

The live server used a dedicated temporary cluster, localhost TCP and SCRAM-SHA-256
authentication. Each database-backed test created its own database, applied real
migrations and dropped that generated database during teardown. The cluster was
stopped after verification. No application `.env`, development database, or real
investigation artifacts were changed.

The portable runtime came from the EDB archive linked by the
[official PostgreSQL Windows download page](https://www.postgresql.org/download/windows/).
Binaries, cluster files and session-only startup helpers remain outside the Git
repository. Running the backend does not require those temporary helpers.

## Milestone 3 extension — analysis jobs

The expanded suite passed on the same live PostgreSQL 17.11 runtime:
**53 passed in 52.82 seconds**. SQLite regression: **47 passed, six PostgreSQL-only
checks skipped**. The temporary server was stopped afterward. No application
runtime database was modified.

This adds real subprocess archive inventory, job permissions, cancellation,
explicit retries, stale-claim/lease handling, source/result hash checks and worker
CLI coverage. Timeout behaviour uses a process double. Two additional PostgreSQL
checks verify that simultaneous workers claim distinct jobs and that a racing
cancel/failure produces exactly one terminal audit transition.

The original 40-test result below remains the historical milestone 2 baseline.
Current instructions run the entire expanded suite.

## What the tests establish

The normal suite runs actual case creation, APK intake, hash/original verification,
transaction rollback, pagination, authentication, session revocation/expiry,
case access checks, role grants/removals and migration/schema consistency.

`backend/tests/test_postgres.py` originally added four live-database checks:

1. Eight simultaneous incorrect logins preserve the failure counter and trigger
   the configured account lock, without lost updates.
2. Two concurrent attempts to assign an unowned legacy case produce exactly one
   owner and one assignment audit event.
3. Foreign-key and membership-role constraints reject invalid inserts and leave
   no partially committed rows.
4. Upgrading from the intake-only migration preserves sample IDs, hashes, sizes,
   storage references, original bytes and historical `local-development` actors.
   Legacy cases remain unowned until explicitly assigned.

This is functional integration and targeted concurrency verification, not a load
benchmark, disaster-recovery exercise or production security certification.
Crash recovery, scale testing, backup/restore and network deployment hardening
still require separate validation.

## Repeat against a dedicated PostgreSQL server

Requires PostgreSQL 17, an existing administrative database (normally `postgres`),
and a test-only login with `CREATEDB` permission. Never use a production account.
The fixture does not migrate or drop the administrative database supplied to it.
Only freshly generated `godeep_test_<UUID>` databases are migrated and dropped.

From repository root in PowerShell, after installing `./backend[dev]`:

```powershell
# Use a dedicated test server/account. Replace the placeholder URL privately.
$env:GODEEP_TEST_POSTGRES_ADMIN_URL = "postgresql+psycopg://TEST_USER:TEST_PASSWORD@127.0.0.1:55432/postgres"
.\.venv\Scripts\python.exe -m pytest backend/tests -q
Remove-Item Env:GODEEP_TEST_POSTGRES_ADMIN_URL
```

Percent-encode special characters in URL passwords. Keep the real URL out of Git,
screenshots and shared terminal output. `GODEEP_TEST_POSTGRES_ADMIN_URL` is for the
test harness only; it does not configure the application runtime database.

The fixture changes `GODEEP_DATABASE_URL` only inside each test and restores it
afterward. API and operator-CLI tests therefore use the same isolated test database.

## Optional Docker test server

If Docker is available, `infra/compose.postgres-test.yml` provides an optional
localhost-only test server. This configuration is not the production deployment.

```powershell
$env:GODEEP_TEST_DB_PASSWORD = "REPLACE_WITH_A_RANDOM_TEST_PASSWORD"
docker compose -f infra/compose.postgres-test.yml up -d --wait
# Set GODEEP_TEST_POSTGRES_ADMIN_URL using the same password, URL-encoded as needed.
# User: godeep_test_admin; host: 127.0.0.1; port: 55432; database: postgres.
.\.venv\Scripts\python.exe -m pytest backend/tests -q
docker compose -f infra/compose.postgres-test.yml down
Remove-Item Env:GODEEP_TEST_DB_PASSWORD
```

The container data directory uses tmpfs and is intentionally disposable. The image
tracks PostgreSQL major version 17; the recorded local verification used EDB 17.11
portable binaries rather than this Docker configuration. Docker startup itself
has not been exercised in this environment.

Without `GODEEP_TEST_POSTGRES_ADMIN_URL`, tests use SQLite and explicitly skip the
six live PostgreSQL checks. Do not interpret that run as PostgreSQL verification.

## Milestone 4 — Android static evidence, 20 October 2026

Live PostgreSQL 17.11: **72 passed in 71.07 seconds**. SQLite: **66 passed,
six PostgreSQL-only tests skipped**. Both reported the existing Starlette TestClient
deprecation warning. The temporary PostgreSQL server was stopped after the run.
New coverage includes binary manifest decoding, SDK defaults, inherited component
permissions, review leads, malformed-input bounds, certificate metadata, partial
signing coverage, authenticated adapter discovery and case-scoped results.
Synthetic fixtures do not establish real-world malware detection accuracy or
Android installability. No runtime application database was modified.

## Milestone 5 — DEX identifier triage, 20 October 2026

Live PostgreSQL 17.11: **82 passed in 74.97 seconds**. SQLite: **76 passed,
six PostgreSQL-only tests skipped in 33.15 seconds**. Both retained the existing
Starlette TestClient deprecation warning. Ten new tests cover DEX identifier
references, string candidates, malformed table/header bounds, unsupported formats,
modified UTF-8, output caps and mixed valid/invalid multidex worker processing.
The temporary PostgreSQL server was stopped. These are functional tests using
synthetic table fixtures, not malware-detection or Android-installability benchmarks.
The final worker error-code allowlist adjustment also passed the ten targeted
SQLite DEX tests; Ruff and dependency consistency checks passed.

## Milestone 6 — instruction call-site evidence, 20 October 2026

Live PostgreSQL 17.11: **98 passed in 73.18 seconds**. SQLite: **92 passed,
six PostgreSQL-only tests skipped in 31.14 seconds**. Both reported the existing
Starlette TestClient deprecation warning. The temporary PostgreSQL server stopped
after verification. Ruff and dependency consistency checks passed.

Sixteen new tests cover caller/target identities, ordinary and range invokes,
unused references, payload boundaries, malformed/truncated instructions, invalid
registers and targets, code bounds, missing bodies, native flags, output limits,
unresolved indirect invokes, unreachable instruction labelling and real worker
persistence. Original synthetic fixtures establish parser behaviour, not Android
installability, reachability or real-world malware detection accuracy.

## Milestone 7 — unified static review, 20 October 2026

Live PostgreSQL 17.11: **106 passed in 80.50 seconds**. SQLite: **100 passed,
six PostgreSQL-only tests skipped in 34.03 seconds**. Both retained the existing
Starlette TestClient deprecation warning. The temporary PostgreSQL server stopped
following verification. Ruff lint/format and dependency consistency checks passed.

Eight new tests cover qualified permission context, missing versus unavailable
manifest state, reference-only findings, duplicate suppression and stable IDs,
output caps, grouped network candidates and real case-scoped worker processing
with valid input, broken manifests and malformed DEX members. These are functional
synthetic-fixture tests, not malware detection benchmarks or production certification.

## Milestone 8 — official signature verification, 20 October 2026

Live PostgreSQL 17.11: **118 passed in 83.90 seconds**. SQLite: **112 passed,
six PostgreSQL-only checks skipped in 39.29 seconds**. The explicit official-tool
test variables were set in both runs, so none of the three Java/apksigner checks
were skipped. Both runs retained the existing Starlette TestClient deprecation
warning. The temporary PostgreSQL server stopped afterward. Ruff lint/format,
dependency consistency and diff checks passed.

Twelve new tests cover status/output interpretation, certificate-text boundaries,
unavailable configuration, real process timeout/output bounds, parent-death tool
cleanup, pinned JAR mismatch, freshly signed/unsigned/tampered APK verification
and real case/job/result processing with operator paths excluded from public job
config. Tools: Android Build Tools 35.0.0, apksigner 0.9, OpenJDK 21.0.2. The test
APKs and keys are generated synthetic fixtures; these tests do not certify Android
installability, production containment or malware-detection accuracy.
