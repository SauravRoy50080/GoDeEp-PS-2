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

## Milestone 16 - research binary classification, 21 October 2026

Full PostgreSQL 17.11 suite: **229 passed in 135.39 seconds**. Full SQLite suite:
**223 passed, six PostgreSQL-only checks skipped in 76.97 seconds**. Real
Java/apksigner tests enabled. Existing Starlette TestClient deprecation warning
remains. Temporary PostgreSQL stopped cleanly. Application database unchanged;
no migration or dependency added. Ruff lint/format, dependency, UTF-8 and diff
checks passed.

Thirteen new tests cover duplicate-vector grouping, disjoint stratified splits,
seed and row-order reproducibility, hand-calculated Naive Bayes outputs, metric
arithmetic, null denominators, training-only parameters, per-group evaluation,
invalid/conflicting labels, invalid schemas and values, insufficient unique groups,
JSON CLI artifacts and refusal to overwrite experiments. A separate local run on
the user's supplied feature CSV trained the initial baseline, with held-out test
precision 56.79%, recall 100% on 46 malware-labelled vectors and false-positive
rate 17.50% on 200 benign vectors. These corpus-specific results do not establish
modern APK performance or extraction parity. Test data did not tune the model.
Raw data, split artifacts and model parameters remain outside Git.

## Milestone 17 - validation-only selection, 21 October 2026

Full PostgreSQL 17.11 suite: **239 passed in 133.91 seconds**. Full SQLite suite:
**233 passed, six PostgreSQL-only checks skipped in 76.97 seconds**. Real
Java/apksigner checks enabled. Existing Starlette TestClient deprecation warning
remains. Temporary PostgreSQL stopped cleanly. Application database unchanged;
no dependencies or migration added. Ruff lint/format, dependency, UTF-8 and diff
checks passed.

Ten new tests cover stump hand calculations/tie breaks, no-split and class errors,
objective boundaries and rejection, deterministic selection ranking, reproducible
comparison, research-only artifacts, guarded exclusion of test feature/label reads,
validation perturbations without training-data mutation and exclusive CLI outputs.
The real supplied corpus selected Naive Bayes threshold 0.9999 on validation:
40 TP, 4 FP, 196 TN, 6 FN; precision 90.91%, recall 86.96%, FPR 2.00%. These
validation figures selected the candidate and are optimistically biased. No test
scoring was performed in this stage and no production promotion occurred. Raw
data and candidate artifacts remain outside Git.

## Milestone 18 - tri-state feature compatibility, 21 October 2026

Full PostgreSQL 17.11 suite: **253 passed in 136.79 seconds**. Full SQLite suite:
**247 passed, six PostgreSQL-only checks skipped in 79.63 seconds**. Real
Java/apksigner checks enabled. Existing Starlette TestClient deprecation warning
remains. Temporary PostgreSQL stopped cleanly. Application database unchanged;
no dependencies or migration added. Ruff lint/format, dependency, UTF-8 and diff
checks passed.

Fourteen new tests cover declaration/absence/unknown states, SDK qualifiers,
failed/anomalous phases, namespace and permission element distinctions,
inconsistent parsed structures, hashes/versions/feature order, strict headerless
mapping contracts, unconditional withholding of model input and exclusive CLI
output. An initial fixture expectation was corrected because INTERNET is actually
declared in the fixture; CAMERA is now the tested absent permission. Final full
suites passed. A controlled static-review APK fixture aligned 109 candidate
permissions (2 declared, 107 not declared), leaving 106 features unknown against
the supplied dataset. These counts are feature-alignment checks, not extraction
parity, malware accuracy or permission effectiveness. No inference or training ran.

## Milestone 19 - imported runtime observations, 21 October 2026

Full PostgreSQL 17.11 suite: **278 passed in 145.68 seconds**. Full SQLite suite:
**272 passed, six PostgreSQL-only checks skipped in 84.21 seconds**. Real
Java/apksigner checks enabled. Existing Starlette TestClient deprecation warning
remains. Temporary PostgreSQL stopped cleanly; application database was not
migrated by tests. Apply additive migration 0005_runtime_captures to the application
before using the new API. No package dependencies added. Ruff lint/format,
dependency, UTF-8 and diff checks passed.

Twenty-five new tests cover typed runtime events, unique chronology, timezone/
interval and event bounds, coverage contradictions, malformed JSON and fields,
raw-byte preservation and digest provenance, metadata/summary/list/download,
duplicate import rejection, transaction audit, migration preservation and schema
checks, viewer/analyst/outsider roles, case scope, media/size/hash/original bounds,
missing/tampered/size-mismatched downloads, transaction cleanup and ID collisions.
Database/file work runs in the threadpool around bounded async body streaming.
All traces are synthetic; no APK runtime collection or emulator isolation was
verified. Capture content, APK attribution, timestamps and collector claims are
not independently authenticated. Live collector and report integration remain
pending; intake does not affect priority scores or classifier output.

## Milestone 20 - runtime captures in forensic snapshots, 21 October 2026

Full PostgreSQL 17.11 suite: **293 passed in 159.95 seconds**. Full SQLite suite:
**287 passed, six PostgreSQL-only checks skipped in 90.94 seconds**. Real
Java/apksigner checks enabled. Existing Starlette TestClient deprecation warning
remains. Temporary PostgreSQL stopped cleanly; application database unchanged.
No new migration or package added; the existing 0005 runtime schema is required.
Ruff lint/format, dependency, UTF-8 and diff checks passed.

Fifteen new tests cover runtime-only/combined version-2 reports, analysis-only
version-1 compatibility, explicit selection/counts, empty/duplicate/combined caps,
capture hash/size/input/structure failures, source loss after snapshot, untrusted
summary exclusion, wrong sample/case IDs, failed collection preservation,
report bounds and transactional cleanup. All 55 targeted report/capture checks
passed before full-suite runs. Strict trace decoding is shared by import/report
without changing the structural trace schema. Test traces remain synthetic;
collector attribution, execution and isolation are not independently verified.
No new model training or test-corpus selection took place.

## Milestone 21 - connected workflow review and runtime timeline, 21 October 2026

Before implementation, the existing SQLite suite passed **287 tests with six
PostgreSQL-only skips in 79.43 seconds**. The new all-adapter connected workflow
and OpenAPI checks passed before timeline implementation. Final PostgreSQL 17.11
suite: **314 passed in 179.97 seconds**. Final SQLite suite: **308 passed, six
PostgreSQL-only skips in 102.56 seconds**. Real Java/apksigner tests enabled in
both full runs; existing Starlette TestClient deprecation warning remains.
Temporary test PostgreSQL stopped cleanly. No new migration or dependencies.
Ruff lint/format, dependency, UTF-8 and diff checks passed.

Twenty-one new checks cover every registered adapter through result/report and
comparison APIs, runtime request OpenAPI references, safe local database readiness,
refusal to stop unconfirmed process ownership, timeline ordering across offsets,
filters, inclusive time boundaries, pagination, per-capture duplicate retention,
evidence references, no audit mutation, permissions/case scope, input/source/output
bounds and tampered source metadata. Shared runtime-source validation keeps report
and timeline identity checks aligned. Thirty targeted timeline/workflow/report
checks and six readiness checks passed separately before final suites.

Local development startup is distinct from these tests. A direct Alembic check
reached 0005_runtime_captures (head), but helper/foreground startup became ready
only transiently and later connection attempts timed out across tool invocations.
The owned foreground attempt exited after an invalid/missing lock-file message.
No case/sample records or schema migration were changed during operational checks.
Persistent local startup from a VS Code terminal remains to be verified. Raw logs
stay in ignored local storage. Tests establish implemented functional connections,
not continuous local service availability, live Android sandboxing, calibrated ML
or malware-detection accuracy. See connection-review.md for scope and commands.

## Milestone 22 - offline declared-library advisory claims, 21 October 2026

Full PostgreSQL 17.11 suite: **337 passed in 180.27 seconds**. Full SQLite suite:
**331 passed, six PostgreSQL-only skips in 104.66 seconds**. Real Java/apksigner
checks enabled; existing Starlette TestClient deprecation warning remains.
Temporary PostgreSQL stopped cleanly. Application database was not changed.
No migration or dependency added. Ruff lint/format, dependency, UTF-8 and diff
checks passed.

Twenty-three new tests cover exact coordinates/version boundaries, declaration
hashes, deduplication/evidence caps, unresolved metadata, conflict detection before
truncation, withdrawn/expired claims, pinned hash/size/freshness failures, missing
configuration, strict feed IDs/versions/JSON/schema, feed validation CLI, real
worker runtime configuration, metadata status linkage, report selection and case
scoping. Existing all-adapter workflow now exercises eleven registered adapters.
The final inventory status pointer was additionally verified in a focused worker
integration run. All advisory records are synthetic; no production feed was
configured, no external data was submitted, and no real CVE/packaged-code match
or exploitability claim is established. Priority scoring/model thresholds did not
change. Version ranges and full software-composition analysis remain pending.

## Milestone 23 - bounded DEX invoke operand graphs, 21 October 2026

Full PostgreSQL 17.11 suite: **350 passed in 424.42 seconds**. Full SQLite suite:
**344 passed, six PostgreSQL-only skips in 230.49 seconds**. Real Java/apksigner
checks enabled; existing Starlette TestClient deprecation warning remains.
Temporary PostgreSQL stopped cleanly; application database was not changed.

After full-suite collection, an additional graph-only prototype-length guard and
regression test were added: **31 focused graph/call tests passed**, including that
new test. The full-suite counts above exclude this final additional test. Ruff
lint/format, dependency, UTF-8 and diff checks passed. No dependency or migration
was added.

Coverage includes ordinary/range invoke operands, non-sensitive targets, recursive
node reuse, repeated edges, malformed instruction streams, payload exclusion,
shared multidex budgets, prototype bounds, worker/report integration and case
scope. Existing default sensitive-call parsing remains unchanged. The registered
adapter workflow now includes twelve adapters. Results are bounded per-DEX static
operand graphs: no full call graph, dispatch resolution, entrypoint reachability,
control-flow validation, runtime execution or detection accuracy is established.

## Milestone 24 - printable forensic HTML exports, 21 October 2026

Full SQLite suite: **354 passed, nine skipped in 227.36 seconds**. Six skips
require PostgreSQL; three require explicitly configured official signer tools.
Focused PostgreSQL 17.11 report/export/runtime-report suite: **42 passed in
92.78 seconds**. Temporary PostgreSQL stopped cleanly; the application database
was not changed. A full PostgreSQL suite was not repeated for this presentation
change. Existing Starlette TestClient deprecation warning remains.

After those suites were collected, a lone-surrogate text escaping guard and its
assertions were added; the final **12 HTML export tests passed in 4.14 seconds**.
Ruff lint/format, dependency, UTF-8 and diff checks passed. No dependency or
migration was added. Backend version is 0.25.0.

Tests cover hostile HTML in source strings, deterministic rendering, distinct
source/export hashes, exact UTF-8 byte bounds, malformed source identities,
unsupported schemas, strict numeric JSON, permission/case scoping, tamper rejection,
unchanged JSON snapshots, and real v1/v2 runtime-only/combined API downloads.
Browser print pagination, PDF generation, digital signatures and analyst sign-off
are not verified or implemented. A clearly marked synthetic example was generated
outside the repository; no real sample or investigation data was published.
