# Backend deployment candidate

`infra/compose.backend.yml` defines PostgreSQL, migrations, API and a static
analysis worker. Docker is unavailable on the development host; build, startup,
backup and restore have not been verified here. This is a deployment candidate.

Set distinct private `GODEEP_POSTGRES_ADMIN_PASSWORD` and
`GODEEP_POSTGRES_PASSWORD` values. The latter must be URL-safe because Compose
places it in a database URL. Never commit these values. Optionally configure
`GODEEP_ALLOWED_HOSTS` and `GODEEP_CORS_ORIGINS` as JSON arrays of explicit hosts
and exact HTTP(S) origins. Defaults permit local access only.

```powershell
docker compose -f infra/compose.backend.yml config --quiet
docker compose -f infra/compose.backend.yml up --build -d
docker compose -f infra/compose.backend.yml exec api python -m godeep.cli create-user --username investigator
```

The CLI prompts for a password. Inspect migration and service logs before use.
The API binds to loopback port 8000; configure and validate a TLS reverse proxy
before external exposure. Production settings require PostgreSQL credentials,
absolute evidence storage and explicit hosts. API documentation defaults off.
CORS uses bearer authentication, not cookie credentials. JSON limits are
independent of streamed APK upload limits.

`/api/v1/health/ready` checks database connectivity and schema head
`0006_report_reviews`. It does not test storage capacity, worker activity or a
sandbox. `/api/v1/capabilities` requires authentication and exposes limitations.

Database initialization creates separate administrator and application roles
only on a fresh volume. The application role owns migration objects; separate
migration-only credentials are future hardening. Back up both named volumes and
rehearse a consistent restore. Do not delete volumes to resolve startup errors.
Container images and dependencies still require release pinning and vulnerability
review. The supplied GitHub workflow has not run remotely in this environment.

The worker subprocess is not an Android sandbox. Dedicated isolated Android
infrastructure and collectors remain external prerequisites. Current official
signer-tool ownership checks target Windows; Linux signature-tool integration
requires implementation and validation before that adapter is enabled there.
