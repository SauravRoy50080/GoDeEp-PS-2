"""Credential lifecycle and case isolation with real hashing and migrated SQLite."""

import io
from datetime import timedelta
from uuid import uuid4
from zipfile import ZipFile

import pytest
from alembic import command
from sqlalchemy import select

from godeep.core.security import hasher, token_hash
from godeep.persistence.models import AuditEvent, AuthSession, Case, CaseMember, User, utc_now
from godeep.services.auth import create_user, disable_user
from godeep.services.cases import claim_legacy_case


def login(client, username, password="other-test-password-123"):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def identity(client, app, username):
    user = create_user(app.state.sessions, username, "other-test-password-123")
    token = login(client, username).json()["access_token"]
    return user.id, {"Authorization": f"Bearer {token}"}


def make_case(client):
    response = client.post("/api/v1/cases", json={"name": "Restricted investigation"})
    assert response.status_code == 201
    return response.json()["id"]


def body():
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", "synthetic")
    return buffer.getvalue()


def upload(client, case_id, headers=None):
    return client.post(
        f"/api/v1/cases/{case_id}/samples",
        content=body(),
        headers={
            "X-Filename": "fixture.apk",
            "Content-Type": "application/octet-stream",
            **(headers or {}),
        },
    )


def test_password_hash_and_normalized_unique_users(intake):
    client, app, _ = intake
    user = create_user(app.state.sessions, "Investigator.A", "long-test-password-123")
    assert user.username == "investigator.a"
    assert user.password_hash.startswith("$argon2id$")
    assert hasher.verify(user.password_hash, "long-test-password-123")
    assert "password_hash" not in client.get("/api/v1/auth/me").text
    with pytest.raises(ValueError):
        create_user(app.state.sessions, "INVESTIGATOR.A", "long-test-password-123")
    with pytest.raises(ValueError):
        create_user(app.state.sessions, "valid", "short")


@pytest.mark.parametrize("header", [None, "Basic abc", "Bearer abc", "Bearer " + "x" * 43])
def test_invalid_auth_blocks_all_case_operations(intake, header):
    client, app, _ = intake
    case_id = make_case(client)
    client.headers.pop("Authorization")
    headers = {"Authorization": header} if header else {}
    paths = [
        "/api/v1/cases",
        f"/api/v1/cases/{case_id}",
        f"/api/v1/cases/{case_id}/samples",
        f"/api/v1/cases/{case_id}/audit",
        f"/api/v1/cases/{case_id}/members",
        f"/api/v1/cases/{case_id}/samples/{uuid4()}",
    ]
    for path in paths:
        assert client.get(path, headers=headers).status_code == 401
    assert client.post("/api/v1/cases", json={"name": "Denied"}, headers=headers).status_code == 401
    assert upload(client, case_id, headers).status_code == 401
    assert not app.state.settings.evidence_root.exists()
    assert client.get("/api/v1/health/live").status_code == 200


def test_login_generic_errors_and_no_secret_echo(intake):
    client, _, _ = intake
    unknown = login(client, "unknown").json()
    wrong = login(client, "owner", "wrong-password").json()
    assert unknown == wrong
    secret = "x" * 129
    response = login(client, "owner", secret)
    assert response.status_code == 422 and secret not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    invalid = client.post(
        "/api/v1/auth/login", json={"username": "owner", "password": {"secret": "hidden"}}
    )
    assert invalid.status_code == 422 and "hidden" not in invalid.text


def test_session_hash_expiry_logout_and_disable(intake):
    client, app, _ = intake
    user_id, headers = identity(client, app, "second")
    raw = headers["Authorization"].split()[1]
    with app.state.sessions() as session:
        record = session.get(AuthSession, token_hash(raw))
        assert record is not None and raw != record.token_digest
    assert client.get("/api/v1/auth/me", headers=headers).json()["id"] == user_id
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    headers = {"Authorization": "Bearer " + login(client, "second").json()["access_token"]}
    digest = token_hash(headers["Authorization"].split()[1])
    with app.state.sessions.begin() as session:
        session.get(AuthSession, digest).expires_at = utc_now() - timedelta(seconds=1)
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    headers = {"Authorization": "Bearer " + login(client, "second").json()["access_token"]}
    disable_user(app.state.sessions, "second")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert login(client, "second").status_code == 401


def test_failed_login_lock_and_expiry(intake):
    client, app, _ = intake
    create_user(app.state.sessions, "locked", "other-test-password-123")
    for _ in range(app.state.settings.login_max_attempts):
        assert login(client, "locked", "incorrect").status_code == 401
    assert login(client, "locked").status_code == 401
    with app.state.sessions.begin() as session:
        user = session.scalar(select(User).where(User.username == "locked"))
        assert user.failed_attempts == app.state.settings.login_max_attempts
        user.locked_until = utc_now() - timedelta(seconds=1)
    assert login(client, "locked").status_code == 200
    with app.state.sessions() as session:
        user = session.scalar(select(User).where(User.username == "locked"))
        assert user.failed_attempts == 0 and user.locked_until is None


def test_cross_user_case_and_sample_isolation(intake):
    client, app, _ = intake
    case_id = make_case(client)
    sample_id = upload(client, case_id).json()["id"]
    _, headers = identity(client, app, "outsider")
    assert client.get("/api/v1/cases", headers=headers).json()["total"] == 0
    for suffix in ["", "/samples", "/audit", "/members", f"/samples/{sample_id}"]:
        assert client.get(f"/api/v1/cases/{case_id}{suffix}", headers=headers).status_code == 404
    assert upload(client, case_id, headers).status_code == 404
    assert client.get("/api/v1/cases?limit=1").json()["total"] == 1


def test_viewer_analyst_and_owner_membership_permissions(intake):
    client, app, _ = intake
    case_id = make_case(client)
    user_id, headers = identity(client, app, "member")
    members = f"/api/v1/cases/{case_id}/members"
    assert client.put(members, json={"user_id": user_id, "role": "viewer"}).status_code == 200
    assert client.get("/api/v1/cases", headers=headers).json()["total"] == 1
    assert client.get(f"/api/v1/cases/{case_id}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/cases/{case_id}/audit", headers=headers).status_code == 200
    assert upload(client, case_id, headers).status_code == 403
    assert (
        client.put(
            members, headers=headers, json={"user_id": user_id, "role": "analyst"}
        ).status_code
        == 403
    )
    assert client.put(members, json={"user_id": user_id, "role": "analyst"}).status_code == 200
    assert upload(client, case_id, headers).status_code == 201
    sample = client.get(f"/api/v1/cases/{case_id}/samples", headers=headers).json()["items"][0]
    assert (
        client.get(f"/api/v1/cases/{case_id}/samples/{sample['id']}", headers=headers).status_code
        == 200
    )
    assert client.delete(f"{members}/{user_id}", headers=headers).status_code == 403
    assert client.delete(f"{members}/{user_id}").status_code == 204
    assert client.get(f"/api/v1/cases/{case_id}", headers=headers).status_code == 404
    assert client.get("/api/v1/cases", headers=headers).json()["total"] == 0
    with app.state.sessions() as session:
        assert session.get(CaseMember, (case_id, user_id)) is None
        audit = session.scalars(select(AuditEvent).where(AuditEvent.case_id == case_id)).all()
        assert all(a.actor != "local-development" for a in audit)
        assert next(a for a in audit if a.action == "sample.registered").actor == user_id


def test_owner_cannot_be_demoted_and_roles_cannot_escalate(intake):
    client, app, _ = intake
    case_id = make_case(client)
    owner_id = client.get("/api/v1/auth/me").json()["id"]
    path = f"/api/v1/cases/{case_id}/members"
    assert client.put(path, json={"user_id": owner_id, "role": "viewer"}).status_code == 409
    assert client.delete(f"{path}/{owner_id}").status_code == 409
    assert client.put(path, json={"user_id": owner_id, "role": "owner"}).status_code == 422
    assert client.put(path, json={"user_id": str(uuid4()), "role": "viewer"}).status_code == 404
    assert (
        client.post(
            "/api/v1/cases", json={"name": "Escalation", "owner_id": str(uuid4())}
        ).status_code
        == 422
    )


def test_legacy_cases_require_explicit_assignment(intake):
    client, app, _ = intake
    with app.state.sessions.begin() as session:
        case = Case(name="Unassigned", description="Legacy")
        session.add(case)
        session.flush()
        case_id = case.id
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 404
    assert client.get("/api/v1/cases").json()["total"] == 0
    claim_legacy_case(app.state.sessions, case_id, "owner")
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 200
    with pytest.raises(ValueError):
        claim_legacy_case(app.state.sessions, case_id, "owner")


def test_migration_preserves_existing_cases(intake):
    _, app, config = intake
    # No open transactions. Reconstruct an intake-only database with a legacy row.
    command.downgrade(config, "0001_intake")
    with app.state.engine.begin() as connection:
        from sqlalchemy import text

        case_id = str(uuid4())
        connection.execute(
            text(
                "INSERT INTO cases(id,name,description,created_at) "
                "VALUES (:id, 'Legacy', '', :created)"
            ),
            {"id": case_id, "created": utc_now().isoformat()},
        )
    command.upgrade(config, "head")
    with app.state.sessions() as session:
        case = session.get(Case, case_id)
        assert case.name == "Legacy" and case.owner_id is None
    command.check(config)


def test_permission_removed_during_upload_prevents_publication(intake, monkeypatch):
    client, app, _ = intake
    case_id = make_case(client)
    user_id, headers = identity(client, app, "uploader")
    members = f"/api/v1/cases/{case_id}/members"
    assert client.put(members, json={"user_id": user_id, "role": "analyst"}).status_code == 200
    original_stage = app.state.evidence_store.stage

    def revoke_then_stage():
        with app.state.sessions.begin() as session:
            session.delete(session.get(CaseMember, (case_id, user_id)))
        return original_stage()

    monkeypatch.setattr(app.state.evidence_store, "stage", revoke_then_stage)
    assert upload(client, case_id, headers).status_code == 404
    assert not list(app.state.settings.evidence_root.rglob("*.apk"))
    assert not list(app.state.settings.evidence_root.rglob("*.part"))
    assert client.get(f"/api/v1/cases/{case_id}/samples").json()["total"] == 0


def test_operator_cli_create_and_disable(intake, monkeypatch, capsys):
    import sys

    from godeep import cli

    _, app, _ = intake
    answers = iter(["operator-test-password-123", "operator-test-password-123"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(answers))
    monkeypatch.setattr(sys, "argv", ["godeep.cli", "create-user", "--username", "cli-user"])
    assert cli.main() == 0
    output = capsys.readouterr()
    assert "Created user cli-user" in output.out
    assert "operator-test-password" not in output.out + output.err
    monkeypatch.setattr(sys, "argv", ["godeep.cli", "disable-user", "--username", "cli-user"])
    assert cli.main() == 0
    with app.state.sessions() as session:
        assert not session.scalar(select(User).where(User.username == "cli-user")).is_active


def test_openapi_security_and_public_liveness(intake):
    client, _, _ = intake
    schema = client.get("/openapi.json").json()
    for path, methods in schema["paths"].items():
        if path.startswith("/api/v1/cases"):
            for operation in methods.values():
                assert operation.get("security") == [{"HTTPBearer": []}]
    client.headers.pop("Authorization")
    assert client.get("/api/v1/health/live").status_code == 200
    assert client.post("/api/v1/auth/register", json={}).status_code == 404
