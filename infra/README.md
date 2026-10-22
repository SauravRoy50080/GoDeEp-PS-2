# Infrastructure

`compose.backend.yml` and `Dockerfile.backend` define the API, PostgreSQL,
migrations and static worker. See [deployment](../docs/deployment.md) for setup
and limitations. These definitions have not been executed in Docker here.
Dynamic Android execution requires dedicated isolated hosts; this Compose stack
does not provide an Android sandbox.

An optional disposable PostgreSQL test server is defined in
`compose.postgres-test.yml`. See ../docs/postgresql-verification.md for setup and
recorded live test results. Docker startup was not verified in this environment.
