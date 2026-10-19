# Infrastructure

Deployment definitions will be added after the first persistence and worker
implementation. Planned services: API, PostgreSQL, object storage and task queue.
Dynamic Android execution belongs on dedicated isolated hosts, separate from the
API and evidence store. No production deployment or sandbox configuration is implemented yet.

An optional disposable PostgreSQL test server is defined in
`compose.postgres-test.yml`. See ../docs/postgresql-verification.md for setup and
recorded live test results. Docker startup was not verified in this environment.
