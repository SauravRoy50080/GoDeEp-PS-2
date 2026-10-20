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

## Milestone 9 and previous-step review - 20 October 2026

Live PostgreSQL 17.11: **129 passed in 85.45 seconds**. SQLite: **123 passed,
six PostgreSQL-only checks skipped in 40.64 seconds**. Real Java/apksigner tests
were enabled in both runs. Both reported the existing Starlette TestClient
warning; the temporary PostgreSQL server stopped after verification. Ruff lint,
format, dependency consistency, UTF-8 source/document validation and diff checks passed.

This includes the empty concrete DEX-body regression and ten new resource inventory
tests: declared library properties, path conflicts, unsupported syntax, binary/text
XML URL evidence, network-policy selectors, DTD rejection, parsing/output limits,
embedded DEX/ZIP magic, ELF headers and case-scoped worker results. After the full
runs, a small ABI-label correction for lib/demo.so paths also passed all ten resource
tests: paths without an ABI directory report null rather than treating a filename
as an ABI. These remain functional tests, not malware accuracy benchmarks.

## Milestone 10 - pinned offline threat intelligence, 20 October 2026

Live PostgreSQL 17.11: **147 passed in 85.77 seconds**. SQLite: **141 passed,
six PostgreSQL-only checks skipped in 42.49 seconds**. Real Java/apksigner checks
were enabled in both runs. Both retained the existing Starlette TestClient
warning; the temporary PostgreSQL server stopped after verification. Ruff lint,
format, dependency consistency, UTF-8 source/document and diff checks passed.

Eighteen new tests cover exact indicator normalization/matching, case and URL
scope, duplicate evidence, domain/subdomain separation, conflicting active claims,
expired records, unavailable/stale/future/invalid feeds, duplicate JSON keys and
record IDs, timezone/schema contracts, hash/size/output bounds, local validation
CLI and real worker/API case-scoped results. All threat feed records were synthetic
fixtures. No provider feed was configured for normal application operation and
no intelligence service received APK data. These are functional tests, not a
validation of source truth or malware-detection accuracy.

## Milestone 11 - forensic JSON report snapshots, 20 October 2026

Live PostgreSQL 17.11: **162 passed in 121.34 seconds**. SQLite: **156 passed,
six PostgreSQL-only checks skipped in 71.41 seconds**. Real Java/apksigner tests
remained enabled in both runs. The existing Starlette TestClient warning remains;
the temporary PostgreSQL server stopped after verification. Ruff lint/format,
dependency consistency, UTF-8 source/document and diff checks passed.

Fifteen new tests cover persisted report JSON/hash provenance, prior-schema
upgrade preservation, source selection and same-hash separate registrations,
missing/tampered original and result artifacts, output bounds, snapshot semantics,
report tampering/deletion, roles and case scoping, transaction rollback cleanup,
unavailable analysis phases and exclusive artifact creation under ID collision.
Alembic schema checks and the full upgrade/downgrade suite passed against both
backends with migration 0004_forensic_reports. The application runtime database
was not migrated by these isolated verification runs. No legal certification,
production custody guarantee or malware-detection accuracy is established here.

## Milestone 12 - case-scoped comparison, 20 October 2026

Live PostgreSQL 17.11: **175 passed in 140.20 seconds**. SQLite: **169 passed,
six PostgreSQL-only checks skipped in 88.27 seconds**. Real Java/apksigner tests
were enabled in both runs. The existing Starlette TestClient deprecation warning
remains. The temporary PostgreSQL server on port 55432 stopped cleanly; the
application database on port 55433 was not changed. No migration is introduced.

Thirteen new tests cover semantic permission/component/API changes, evidence
references, sample-specific IDs and selectors, canonical network observations,
certificate identity, coverage/configuration/tool/SDK cautions, truncation and
output bounds, real worker/API integration, role and case scoping, explicit run
selection, incompatible versions, incomplete jobs, source tampering and malformed
source structure. Ruff lint/format, dependency, UTF-8 and diff checks passed.
These are functional checks, not malware-detection accuracy measurements.

## Milestone 13 - loading and evasion review leads, 21 October 2026

Final full-suite PostgreSQL 17.11 run: **184 passed in 133.69 seconds**.
SQLite: **178 passed, six PostgreSQL-only checks skipped in 86.50 seconds**.
Real Java/apksigner tests were enabled in both runs. The existing Starlette
TestClient deprecation warning remains. Temporary PostgreSQL on port 55432 stopped
cleanly; application PostgreSQL on port 55433 was not changed. No migration added.

Nine new tests cover the four API-rule categories, identifier/call distinction,
reference suppression, caller/offset provenance, unrelated rule exclusion,
duplicate evidence, bounds, partial source coverage, file-header candidates,
deterministic input-scoped IDs, catalog exposure, real worker analysis, case
scoping and forensic JSON report creation. The existing catalog test was updated
for the ninth adapter after the initial suite detected its outdated expected set.
Both complete suites passed after that correction. Lint, format, dependency,
UTF-8 and diff checks passed. Functional checks do not measure evasion detection
accuracy; anti-emulation and encrypted payload detection remain unevaluated.

## Milestone 14 - explained static priority policy, 21 October 2026

PostgreSQL 17.11 full suite: **197 passed in 143.51 seconds**. SQLite full suite:
**191 passed, six PostgreSQL-only checks skipped in 89.14 seconds**. Real
Java/apksigner checks were enabled in both runs. The existing Starlette TestClient
deprecation warning remains. Temporary PostgreSQL stopped cleanly. Application
PostgreSQL on port 55433 was unchanged; this step adds no migration or dependencies.

Thirteen new tests cover zero-score interpretation, weak identifier weighting,
rule deduplication, category caps and exact contribution reconciliation, benign/
suspicious/malicious source assertions, conflicting claims, repeated matches,
unavailable/expired feed exclusions, unknown rules, missing evidence, permission
non-scoring, deterministic gaps, real subprocess pinned-feed delivery, source
finding/feed references, case scoping and forensic JSON report creation. Catalog
expectations include the tenth registered adapter. Ruff lint/format, dependency,
UTF-8 and diff checks passed. These checks validate functional arithmetic and
integration, not calibration, malware probability or detection accuracy.

## Milestone 15 - offline priority evaluation, 21 October 2026

Full PostgreSQL 17.11 suite: **216 passed in 137.44 seconds**. Full SQLite suite:
**210 passed, six PostgreSQL-only checks skipped in 78.37 seconds**. Real
Java/apksigner tests were enabled. The existing Starlette TestClient deprecation
warning remains. Temporary PostgreSQL stopped cleanly; application PostgreSQL was
not changed. No dependency or migration added. Ruff lint/format, dependency,
UTF-8 and diff checks passed.

Nineteen new tests validate confusion arithmetic, selective coverage and positive
abstention recall bounds, undefined metrics, missing predictions, duplicate APK
hashes, cross-split group leakage, label/target contracts, provenance, path/hash
and input identity, version/policy consistency, duplicate/non-finite JSON,
explicit splits, profile flags, size bounds and exclusive CLI output creation.
All test labels/results are synthetic. No real corpus was evaluated, no weights
were calibrated, and no model was trained. These counts do not measure detection
accuracy. Real-data schema/label review is the next prerequisite.
