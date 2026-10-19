# GoDeEp — PS-02

AI-assisted Android application security and forensic analysis platform.

The backend is being built around evidence preservation, static and dynamic
analysis, threat intelligence, and explainable findings for investigators.

## Current status

Backend scaffold only. The API exposes a liveness endpoint. APK ingestion,
analysis engines, database persistence, authentication, sandbox execution,
risk scoring, and AI assistance are planned and are not implemented yet.
No frontend is included.

## Development

Requires Python 3.12 or newer. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e "./backend[dev]"
Copy-Item backend/.env.example backend/.env
python -m uvicorn godeep.main:app --app-dir backend/src --reload --host 127.0.0.1
```

API documentation: http://127.0.0.1:8000/docs
Liveness: http://127.0.0.1:8000/api/v1/health/live

The liveness response confirms only that the API process responds; it does
not report database, worker, or sandbox readiness.

```powershell
python -m pytest backend/tests
python -m ruff check backend
```

## Layout

```text
backend/
  src/godeep/
    api/v1/          # Versioned routes
    core/            # Configuration and application concerns
    schemas/         # API contracts
    domain/          # Cases, samples, evidence, findings (planned)
    services/        # Use-case orchestration (planned)
    persistence/     # Database repositories (planned)
    storage/         # Evidence storage (planned)
    analysis/        # Static, dynamic and correlation pipelines (planned)
    integrations/    # External analyzer adapters (planned)
    workers/         # Background jobs (planned)
    reporting/       # Evidence-linked reports (planned)
    ai/              # Grounded assistance (planned)
  tests/
  migrations/
docs/
infra/
```

See [architecture](docs/architecture.md), [development roadmap](docs/roadmap.md),
and [research patterns](docs/repository-patterns.md).
Never commit APK samples, forensic evidence, credentials, or private case data.
