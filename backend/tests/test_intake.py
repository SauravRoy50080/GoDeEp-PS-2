"""Intake integration checks using synthetic ZIP containers, not malware samples."""

import hashlib
import io
import struct
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest
from sqlalchemy import event, inspect
from sqlalchemy.exc import SQLAlchemyError

from godeep.persistence.models import AuditEvent, Sample


def apk(entries=None):
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        for name, contents in entries or [("AndroidManifest.xml", b"synthetic manifest")]:
            archive.writestr(name, contents)
    return stream.getvalue()


def create(client, name="Investigation"):
    response = client.post("/api/v1/cases", json={"name": name, "description": "Synthetic"})
    assert response.status_code == 201
    return response.json()["id"]


def upload(client, case_id, body, name="fixture.apk", headers=None):
    return client.post(
        f"/api/v1/cases/{case_id}/samples",
        content=body,
        headers={"Content-Type": "application/octet-stream", "X-Filename": name, **(headers or {})},
    )


def test_case_validation_pagination_and_audit(intake):
    client, _, _ = intake
    assert client.post("/api/v1/cases", json={"name": "  "}).status_code == 422
    first = create(client)
    create(client, "Second")
    page = client.get("/api/v1/cases?limit=1&offset=1").json()
    assert page["total"] == 2 and len(page["items"]) == 1
    assert client.get("/api/v1/cases?limit=101").status_code == 422
    assert client.get(f"/api/v1/cases/{first}").json()["created_at"].endswith("Z")
    audit = client.get(f"/api/v1/cases/{first}/audit").json()
    assert audit["total"] == 1 and audit["items"][0]["action"] == "case.created"


def test_original_integrity_and_case_scoping(intake):
    client, app, _ = intake
    case_id = create(client)
    payload = apk()
    result = upload(client, case_id, payload)
    assert result.status_code == 201, result.text
    sample = result.json()
    assert sample["sha256"] == hashlib.sha256(payload).hexdigest()
    assert sample["size_bytes"] == len(payload)
    assert sample["intake_status"] == "structure_checked"
    assert "storage_key" not in sample
    with app.state.sessions() as session:
        stored = session.get(Sample, sample["id"])
        assert (app.state.settings.evidence_root / stored.storage_key).read_bytes() == payload
    other = create(client, "Other")
    assert client.get(f"/api/v1/cases/{other}/samples/{sample['id']}").status_code == 404
    assert client.get(f"/api/v1/cases/{case_id}/samples").json()["total"] == 1
    assert client.get(f"/api/v1/cases/{case_id}/samples/{sample['id']}").status_code == 200
    assert client.get(f"/api/v1/cases/{case_id}/audit").json()["total"] == 2
    # Identical bytes are registered separately, preserving each submission.
    second = upload(client, case_id, payload).json()
    assert second["sha256"] == sample["sha256"] and second["id"] != sample["id"]


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not an apk",
        apk([("classes.dex", b"demo")]),
        apk([("AndroidManifest.xml", b"")]),
        apk([("AndroidManifest.xml", b"x"), ("../escape", b"x")]),
        apk([("AndroidManifest.xml", b"x"), ("C:/bad", b"x")]),
    ],
)
def test_invalid_archive_rejected_without_evidence(intake, body):
    client, app, _ = intake
    case_id = create(client)
    assert upload(client, case_id, body).status_code == 422
    assert client.get(f"/api/v1/cases/{case_id}/samples").json()["total"] == 0
    assert not list(app.state.settings.evidence_root.rglob("*.part"))
    assert not list(app.state.settings.evidence_root.rglob("*.apk"))


def test_header_and_case_validation(intake):
    client, _, _ = intake
    case_id = create(client)
    assert upload(client, case_id, apk(), "../escape.apk").status_code == 422
    assert upload(client, case_id, apk(), "file.txt").status_code == 422
    assert (
        upload(client, case_id, apk(), headers={"Content-Type": "multipart/form-data"}).status_code
        == 415
    )
    assert upload(client, str(uuid4()), apk()).status_code == 404
    assert upload(client, case_id, apk(), headers={"Content-Length": "-1"}).status_code == 400


def test_streamed_limit_without_content_length(intake):
    client, app, _ = intake
    case_id = create(client)
    app.state.settings.max_upload_bytes = 32
    assert upload(client, case_id, apk()).status_code == 413
    response = upload(client, case_id, iter([b"x" * 20, b"y" * 20]))
    assert response.status_code == 413
    assert not list(app.state.settings.evidence_root.rglob("*.part"))


def test_archive_resource_limits(intake):
    client, app, _ = intake
    case_id = create(client)
    app.state.settings.max_archive_entries = 1
    assert (
        upload(client, case_id, apk([("AndroidManifest.xml", b"x"), ("extra", b"x")])).status_code
        == 422
    )
    app.state.settings.max_archive_entries = 100
    app.state.settings.max_uncompressed_bytes = 100
    assert upload(client, case_id, apk([("AndroidManifest.xml", b"x" * 101)])).status_code == 422
    app.state.settings.max_uncompressed_bytes = 10000
    app.state.settings.max_central_directory_bytes = 10
    assert upload(client, case_id, apk()).status_code == 422


def test_duplicate_and_symlink_members(intake):
    client, _, _ = intake
    case_id = create(client)
    with pytest.warns(UserWarning):
        duplicate = apk([("AndroidManifest.xml", b"x"), ("AndroidManifest.xml", b"y")])
    assert upload(client, case_id, duplicate).status_code == 422
    member = ZipInfo("link")
    member.create_system = 3
    member.external_attr = 0o120777 << 16
    assert (
        upload(
            client, case_id, apk([("AndroidManifest.xml", b"x"), (member, b"target")])
        ).status_code
        == 422
    )


def test_encrypted_and_corrupt_directory(intake):
    client, _, _ = intake
    case_id = create(client)
    body = bytearray(apk())
    central = body.index(b"PK\x01\x02")
    struct.pack_into("<H", body, central + 8, 1)
    assert upload(client, case_id, bytes(body)).status_code == 422
    malformed = bytearray(apk())
    end = malformed.rfind(b"PK\x05\x06")
    struct.pack_into("<L", malformed, end + 16, len(malformed) + 100)
    assert upload(client, case_id, bytes(malformed)).status_code == 422


def test_failed_transaction_removes_published_file_and_audit(intake):
    client, app, _ = intake
    case_id = create(client)

    def fail_sample(_mapper, _connection, _target):
        raise SQLAlchemyError("simulated storage metadata failure")

    event.listen(Sample, "before_insert", fail_sample)
    try:
        response = upload(client, case_id, apk())
    finally:
        event.remove(Sample, "before_insert", fail_sample)
    assert response.status_code == 503
    assert "simulated" not in response.text
    assert not list(app.state.settings.evidence_root.rglob("*.apk"))
    assert not list(app.state.settings.evidence_root.rglob("*.part"))
    assert client.get(f"/api/v1/cases/{case_id}/audit").json()["total"] == 1


def test_database_survives_new_session(intake):
    client, app, _ = intake
    case_id = create(client)
    app.state.engine.dispose()
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 200
    with app.state.sessions() as session:
        assert session.query(AuditEvent).count() == 1


def test_migration_upgrade_and_downgrade(intake):
    from alembic import command

    _, app, config = intake
    command.upgrade(config, "head")
    assert {"cases", "samples", "audit_events"} <= set(inspect(app.state.engine).get_table_names())
    command.check(config)
    command.downgrade(config, "base")
    assert "cases" not in inspect(app.state.engine).get_table_names()
    command.upgrade(config, "head")


def test_storage_failure_is_sanitized_and_staging_cleaned(intake, monkeypatch):
    client, app, _ = intake
    case_id = create(client)

    def fail_publish(*_):
        raise OSError("private filesystem detail")

    monkeypatch.setattr(app.state.evidence_store, "publish", fail_publish)
    response = upload(client, case_id, apk())
    assert response.status_code == 503
    assert "private" not in response.text
    assert not list(app.state.settings.evidence_root.rglob("*.part"))
    assert client.get(f"/api/v1/cases/{case_id}/samples").json()["total"] == 0


def test_case_and_audit_commit_together(intake):
    client, _, _ = intake

    def fail_audit(_mapper, _connection, _target):
        raise SQLAlchemyError("simulated audit failure")

    event.listen(AuditEvent, "before_insert", fail_audit)
    try:
        response = client.post("/api/v1/cases", json={"name": "Must roll back"})
    finally:
        event.remove(AuditEvent, "before_insert", fail_audit)
    assert response.status_code == 503
    assert client.get("/api/v1/cases").json()["total"] == 0


def test_extremely_large_declared_length_is_rejected(intake):
    client, _, _ = intake
    case_id = create(client)
    assert upload(client, case_id, b"x", headers={"Content-Length": "9" * 5000}).status_code == 413
