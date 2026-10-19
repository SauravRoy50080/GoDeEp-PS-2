# Milestone 1: local evidence intake

Implemented: cases, raw APK upload, SHA-256, original-byte storage, sample metadata,
paginated queries and transactional intake events. Authentication and case permissions
were added in milestone 2; analysis jobs, Android parsing and malware verdicts remain
future work. Run on localhost with synthetic fixtures pending deployment hardening.
See [authentication setup](authentication.md) before using these endpoints.

## Install and migrate (repository root, PowerShell)

```powershell
.\.venv\Scripts\python.exe -m pip install -e "./backend[dev]"
Copy-Item backend/.env.example backend/.env
```

Edit `GODEEP_DATABASE_URL` in `backend/.env` to point to an existing PostgreSQL
database with a dedicated user. The password example must be replaced. No
PostgreSQL service is installed automatically. Apply migrations explicitly:

```powershell
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m uvicorn godeep.main:app --app-dir backend/src --host 127.0.0.1
```

For local evaluation without PostgreSQL, explicitly choose a persistent SQLite
database outside Git. This is a development/test option, not PostgreSQL verification:

```powershell
New-Item -ItemType Directory -Force backend/data | Out-Null
$env:GODEEP_DATABASE_URL = "sqlite:///backend/data/local.db"
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
```

Keep that environment variable in the shell when starting Uvicorn. Environment
variables override `.env`. Liveness remains independent of database readiness.

## API walkthrough

First log in as described in the authentication guide. Set `$headers` to
`@{Authorization="Bearer $token"}` using the returned session token.

```powershell
$case = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/cases `
  -Headers $headers -ContentType application/json -Body '{"name":"Synthetic test","description":"Local evaluation"}'
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/cases/$($case.id)/samples" `
  -ContentType application/octet-stream -Headers (@{Authorization="Bearer $token";"X-Filename"="fixture.apk"}) -InFile ./fixture.apk
Invoke-RestMethod -Headers $headers "http://127.0.0.1:8000/api/v1/cases/$($case.id)/samples?limit=25&offset=0"
Invoke-RestMethod -Headers $headers "http://127.0.0.1:8000/api/v1/cases/$($case.id)/audit"
```

Upload uses the **raw file as the request body**, not multipart. Extension and
content type are preliminary checks only. The original filename is metadata;
server-generated UUIDs determine evidence paths. Repeated submissions are distinct
records even when hashes match. Storage paths are not exposed by public schemas.

## Bounds and evidence meaning

- Default maximum upload: 200 MiB; actual streamed byte count is enforced even
  without Content-Length. A single incoming ASGI chunk can exceed this limit in
  transport memory before rejection; production needs proxy and concurrency limits.
- ZIP directory is capped at 8 MiB and 10,000 entries; declared expansion at 1 GiB.
- Rejects missing/empty root manifest, unsafe paths, duplicate names, encrypted
  members, symlinks, multipart ZIPs and ZIP64. No extraction or execution occurs.
- `structure_checked` means bounded container triage only. It does not establish
  a valid binary manifest, installability, signature validity, CRC integrity, benign
  behaviour or successful Android analysis. Resource values in ZIP metadata are
  untrusted; later workers need independent limits.
- SHA-256 covers the uploaded original bytes. The local store is not WORM storage.
  External edits remain possible; later integrity checks and access controls are needed.
- Staging files are cleaned on ordinary failures; published files are removed if
  metadata commit fails. Filesystem and database changes are not a distributed
  transaction: process crashes can leave orphan files. Startup reconciliation and
  crash recovery are future work; never auto-delete unexplained evidence.
- Audit rows are committed with their mutation. They are application events, not
  an append-only, tamper-evident chain of custody. Actor is
  the authenticated user UUID for new mutations; old `local-development` events
  remain unchanged. Rejected intake logging
  and download events are not implemented.

## Verification

Tests use synthetic ZIPs and file-backed SQLite migrated through Alembic. They
cover persistence, case scoping, pagination, upload bounds, malformed structures,
hash/original integrity, failure cleanup and migration/schema consistency.
Live PostgreSQL must be verified in a PostgreSQL-equipped environment before
calling this production-ready.
