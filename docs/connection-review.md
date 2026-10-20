# Backend connection review - 21 October 2026

## What was exercised

The pre-change full SQLite regression suite passed: 287 tests, six PostgreSQL-only
skips. Dependency, Ruff lint and format checks passed. A new controlled workflow
executes every one of the ten registered adapters on the same original fixture
APK, verifies result identity/version, imports runtime evidence, generates and
downloads a combined report, uploads a changed APK and compares static runs. After
timeline implementation it also checks the runtime view. Optional tools/feed
availability remains explicit rather than becoming false success claims.

Existing tests cover authentication, roles, intake bounds, original hashes,
queue/worker state, adapter evidence, source coverage, artifact tampering, migrations,
comparison permissions, report snapshots and offline research contracts. Synthetic
fixtures validate function and integration, not malware detection accuracy.

## Gaps fixed

1. Streaming runtime capture POST had server-side validation but no OpenAPI request
   schema. The API now exposes a namespaced RuntimeTrace schema with resolvable
   references. Streaming/body limits and authorization order are unchanged.
2. Development PostgreSQL helper equated pg_ctl PID visibility with readiness. A
   real Alembic connection confirmed revision 0005 while process status disagreed.
   The helper now probes only the configured local PostgreSQL host/port via a bounded
   authenticated SELECT, keeps credentials out of output, skips starting an already
   reachable database and refuses stop when managed ownership is unconfirmed.
3. Runtime source verification is shared by reports and timeline views, avoiding
   drift between hash, size, identity and trace-validation checks.

## Local startup limitation

During this managed session, one development connection reached
0005_runtime_captures (head). Another startup became reachable while launching but
was not reachable on a later invocation. A persistent local API/database session
is therefore not confirmed. The owned foreground attempt later exited after an
invalid/missing lock-file message. No new migration or case/sample changes were
applied to application data. Use the repository VS Code terminal to start
and verify the development database before launching API/worker processes:

```powershell
.\.venv\Scripts\python.exe backend/scripts/postgres_dev.py start
.\.venv\Scripts\python.exe backend/scripts/postgres_dev.py status
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini current
```

This is separate from isolated PostgreSQL regression databases. A liveness response
still does not prove database/worker/emulator readiness.

## Intentional unconnected areas

Research models remain outside production inference: the 215-feature dataset lacks
verified extractor parity. Runtime captures are imported collector assertions,
not verified emulator execution. There is no live collector, calibrated malware
probability, AI explanation service, production sandbox or teammate frontend in
this backend change. These are pending capabilities, not connections silently
assumed to work. See the regression results appended to postgresql-verification.md
for the final suite counts following this review and timeline addition.

## Final regression results

PostgreSQL: 314 passed in 179.97 seconds. SQLite: 308 passed, six PostgreSQL-only
skips in 102.56 seconds. Real signer tests enabled. Lint/format/dependencies,
UTF-8 and diff checks passed; the existing TestClient deprecation warning remains.
The isolated test server stopped cleanly. Persistent local availability remains
separate from these passing workflow checks.
