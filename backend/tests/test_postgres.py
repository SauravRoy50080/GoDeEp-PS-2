"""Live PostgreSQL-only transaction, locking and upgrade preservation checks."""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from fastapi import HTTPException
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from godeep.persistence.models import AuditEvent, Case, CaseMember, Sample, User, utc_now
from godeep.services.auth import create_user, login
from godeep.services.cases import claim_legacy_case

pytestmark = pytest.mark.skipif(
    not os.environ.get("GODEEP_TEST_POSTGRES_ADMIN_URL"),
    reason="Requires an explicitly configured live PostgreSQL server",
)


def test_concurrent_failed_logins_preserve_lockout_counter(intake):
    _, app, _ = intake
    user = create_user(app.state.sessions, "concurrent", "concurrent-test-password-123")
    barrier = Barrier(8)

    def attempt(_):
        barrier.wait(timeout=10)
        try:
            login(app.state.sessions, app.state.settings, "concurrent", "wrong-password")
            return 200
        except HTTPException as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results == [401] * 8
    with app.state.sessions() as session:
        saved = session.get(User, user.id)
        assert saved.failed_attempts == app.state.settings.login_max_attempts
        assert saved.locked_until > utc_now()
    with pytest.raises(HTTPException) as blocked:
        login(app.state.sessions, app.state.settings, "concurrent", "concurrent-test-password-123")
    assert blocked.value.status_code == 401


def test_concurrent_legacy_assignment_has_one_winner(intake):
    _, app, _ = intake
    first = create_user(app.state.sessions, "first", "concurrent-test-password-123")
    second = create_user(app.state.sessions, "second", "concurrent-test-password-123")
    with app.state.sessions.begin() as session:
        case = Case(name="Legacy", description="Race fixture")
        session.add(case)
        session.flush()
        case_id = case.id
    barrier = Barrier(2)

    def claim(username):
        barrier.wait(timeout=10)
        try:
            claim_legacy_case(app.state.sessions, case_id, username)
            return "assigned"
        except ValueError:
            return "already-owned"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, [first.username, second.username]))
    assert sorted(results) == ["already-owned", "assigned"]
    with app.state.sessions() as session:
        assert session.get(Case, case_id).owner_id in {first.id, second.id}
        events = session.scalars(select(AuditEvent).where(AuditEvent.case_id == case_id)).all()
        assert len(events) == 1 and events[0].action == "case.legacy_assigned"


def test_foreign_key_and_role_constraints_enforced(intake):
    client, app, _ = intake
    owner_id = client.get("/api/v1/auth/me").json()["id"]
    case_id = client.post("/api/v1/cases", json={"name": "Constraints"}).json()["id"]
    with pytest.raises(IntegrityError), app.state.sessions.begin() as session:
        session.add(CaseMember(case_id=str(uuid4()), user_id=owner_id, role="viewer"))
    with pytest.raises(IntegrityError), app.state.sessions.begin() as session:
        session.add(CaseMember(case_id=case_id, user_id=owner_id, role="administrator"))
    with app.state.sessions() as session:
        assert session.scalars(select(CaseMember)).all() == []


def test_auth_migration_preserves_original_sample_and_historical_audit(intake, tmp_path):
    _, app, config = intake
    command.downgrade(config, "0001_intake")
    case_id, sample_id, event_id = str(uuid4()), str(uuid4()), str(uuid4())
    original = b"synthetic original bytes for upgrade preservation"
    digest = hashlib.sha256(original).hexdigest()
    key = f"originals/{sample_id}.apk"
    target = app.state.settings.evidence_root / key
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    now = utc_now()
    with app.state.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO cases(id,name,description,created_at) "
                "VALUES (:id,'Legacy','','2026-10-19T00:00:00Z')"
            ),
            {"id": case_id},
        )
        connection.execute(
            text(
                "INSERT INTO samples(id,case_id,original_name,sha256,size_bytes,"
                "storage_key,intake_status,created_at) VALUES "
                "(:id,:case_id,'fixture.apk',:digest,:size,:key,'structure_checked',:now)"
            ),
            {
                "id": sample_id,
                "case_id": case_id,
                "digest": digest,
                "size": len(original),
                "key": key,
                "now": now,
            },
        )
        connection.execute(
            text(
                "INSERT INTO audit_events(id,case_id,action,actor,subject_id,"
                "details,created_at) VALUES (:id,:case_id,'sample.registered',"
                "'local-development',:sample_id,'{}',:now)"
            ),
            {"id": event_id, "case_id": case_id, "sample_id": sample_id, "now": now},
        )
    command.upgrade(config, "head")
    command.check(config)
    with app.state.sessions() as session:
        assert session.get(Case, case_id).owner_id is None
        saved = session.get(Sample, sample_id)
        assert saved.sha256 == digest and saved.size_bytes == len(original)
        assert (app.state.settings.evidence_root / saved.storage_key).read_bytes() == original
        assert session.get(AuditEvent, event_id).actor == "local-development"
