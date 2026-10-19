# Milestone 2: authentication and case access

Implemented: operator-created accounts, Argon2id password hashes, opaque bearer
sessions, logout, user disabling, case ownership and analyst/viewer membership.
No frontend authentication code, public registration or external identity provider
is included. Existing APK intake contracts are unchanged except authentication
is now mandatory. Liveness and OpenAPI documentation remain public.

## Upgrade and create the first user

From repository root, in the same environment used for the database:

```powershell
.\.venv\Scripts\python.exe -m pip install -e "./backend[dev]"
.\.venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
.\.venv\Scripts\python.exe -m godeep.cli create-user --username investigator
```

Passwords are entered twice through a hidden interactive prompt, not command-line
flags. Usernames are case-insensitive ASCII identifiers of 3-80 characters using
letters, digits, dots, underscores or dashes. Passwords require 15-128 characters
and are not trimmed or silently truncated. Accounts are created by a trusted local
operator with database access, not by an unauthenticated API request.

Default sessions last 8 hours (`GODEEP_SESSION_TTL_SECONDS`, 60-86400). Known accounts
lock for 15 minutes after 5 failed logins; settings are
`GODEEP_LOGIN_MAX_ATTEMPTS` and `GODEEP_LOGIN_LOCK_SECONDS`. Authentication failures
share a generic 401 message. Successful login after lock expiry clears failures.

## Login and Swagger

Start the API on localhost as described in the intake guide. In `/docs`, call
`POST /api/v1/auth/login` with username and password. Copy the returned token into
Swagger's **Authorize** button. Never paste passwords/tokens into Git or reports.
`GET /api/v1/auth/me` returns the user's UUID and username.

The login response has `access_token`, `token_type: bearer` and `expires_at`.
Send `Authorization: Bearer <token>` on all case/sample/audit/member requests.
Tokens are cryptographically random (32 bytes); only SHA-256 token digests are
stored in the database. Passwords use Argon2id, not SHA-256. No browser cookies
are issued. Choose browser credential storage/transport deliberately when the
frontend authentication flow is implemented; do not default to localStorage.

`POST /api/v1/auth/logout` revokes the current session. Other sessions are not
revoked by that endpoint. To disable an account and revoke all its sessions:

```powershell
.\.venv\Scripts\python.exe -m godeep.cli disable-user --username investigator
```

There is no re-enable/password-reset endpoint yet. Disabled users and revoked or
expired sessions cannot authenticate subsequent requests. In-flight requests are
not force-cancelled by logout; upload permissions are checked again before evidence
publication but session status is established at request authentication time.

## Case permissions

| Operation | Owner | Analyst member | Viewer member | Unrelated user |
|---|---|---|---|---|
| Read case, sample metadata and audit events | Yes | Yes | Yes | No |
| Upload APK evidence | Yes | Yes | No | No |
| List/change/remove memberships | Yes | No | No | No |
| Create a new owned case | Yes | Yes | Yes | Any active authenticated account |

Every new case belongs to its creator. List counts and pagination are scoped to
accessible cases. Outsiders receive 404 for another case; known members trying a
forbidden operation receive 403. Owner permissions cannot be changed through the
membership API. Ownership transfer is not implemented.

- `GET /api/v1/cases/{case_id}/members`: owner lists explicit memberships.
- `PUT /api/v1/cases/{case_id}/members`: owner adds/updates
  `{"user_id":"<UUID>","role":"analyst"}` or `viewer`.
- `DELETE /api/v1/cases/{case_id}/members/{user_id}`: owner removes a member.

Provision the teammate's account via CLI and use its printed user UUID for grants.
The owner is represented by `owner_id` on the case, not a membership-list entry.
Role changes/removals take effect for subsequent access checks even if the user
still has a valid login token. Case creation, upload and membership mutations use
the authenticated UUID as audit actor. Membership events commit atomically with
their changes. Login and operator account actions do not yet have a durable
security-event audit log; case audit is not tamper-evident storage.

## Cases created before authentication

Migration `0002_auth` keeps legacy cases and their evidence intact with a null
owner. No account automatically inherits them. A trusted operator must assign one:

```powershell
.\.venv\Scripts\python.exe -m godeep.cli claim-case --case-id CASE_UUID --username investigator
```

This works only for an unowned case and creates a `case.legacy_assigned` event.
Existing `local-development` audit actors remain unchanged; attribution is not
retroactively invented. Back up databases before migration. Downgrades are for
disposable test databases; they remove authentication and permission records.

## Validation and deployment limits

Tests use real Argon2 hashing and migrated databases. The full suite passed on
live PostgreSQL 17.11, including eight concurrent failed logins and competing
legacy-case assignments. See [verification results](postgresql-verification.md).
SQLite does not provide the same row-lock semantics and remains a local testing option.

Account lockouts do not replace ingress/global rate limits. Unknown-account attempts
still perform a dummy hash verification; before network deployment add distributed
rate limits, request-size limits on auth JSON, HTTPS, trusted-proxy configuration,
security-event monitoring, MFA/SSO/recovery design and deployment-specific tests.
Argon2 runs in worker threads; set bounded server concurrency for actual hosting.
No production security certification is claimed by this milestone.

Guidance: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
