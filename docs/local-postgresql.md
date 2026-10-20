# Persistent local PostgreSQL development database

The earlier connection to 127.0.0.1:5432 had no reachable server. The PostgreSQL
integration-test server is temporary and stopped after tests. KeyboardInterrupt
inside psycopg.connect indicates an interrupted connection, not a migration error.

A new empty application database, godeep, is prepared on 127.0.0.1:55433. Migration
0004_forensic_reports and the report table were verified against this database.
The application role cannot create roles/databases and is not a superuser.
Credentials are only in ignored backend/.env and operator metadata under ignored
backend/data. Existing test databases and evidence were not deleted or imported.

Start it from your own VS Code PowerShell terminal, at repository root:

```powershell
.\.venv\Scripts\python.exe backend/scripts/postgres_dev.py start
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini current
```

Expected revision: 0004_forensic_reports. upgrade head can be rerun safely.
If a previous shell variable overrides the saved .env configuration, clear it:

```powershell
Remove-Item Env:GODEEP_DATABASE_URL -ErrorAction SilentlyContinue
```

Status and clean shutdown:

```powershell
.\.venv\Scripts\python.exe backend/scripts/postgres_dev.py status
.\.venv\Scripts\python.exe backend/scripts/postgres_dev.py stop
```

Run start after a reboot. The helper opens no visible window and prints no
credentials. The server must be started from the user's terminal for ongoing work;
the agent's provisioning server was stopped cleanly after verification.
The portable runtime and persistent cluster reside in the local Codex workspace
outside Git. Do not move those directories without updating local configuration.
This is a local-machine development setup, not an installed Windows service or
a server bundled with the repository. Teammates configure their own PostgreSQL.

The new database has no investigator accounts. Create one with a hidden prompt:

```powershell
.\.venv\Scripts\python.exe -m godeep.cli create-user --username investigator
```

See authentication.md for login. PostgreSQL API and Alembic connections now have
a five-second timeout; SQLite handling is unchanged. Local database setup and
migration were verified; migration/health regression tests also passed. Production
backups, service installation and operational hardening remain separate work.
