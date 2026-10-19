# Database migrations

Apply from repository root: `python -m alembic -c backend/alembic.ini upgrade head`.
Configuration comes from `GODEEP_DATABASE_URL` or `backend/.env`. Migration
0001 creates cases, samples and audit_events. API startup does not create tables.
Downgrades remove data; use only disposable test databases for downgrade checks.
See ../../docs/intake-development.md.
