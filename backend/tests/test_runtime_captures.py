"""Bounded imported runtime traces preserve attribution, coverage and raw bytes."""

import copy
import hashlib
import json
from uuid import uuid4

import pytest
from alembic import command
from fastapi import HTTPException
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError
from test_jobs import fixture_sample

from godeep.persistence.models import AuditEvent, RuntimeCapture, Sample
from godeep.services.auth import create_user
from godeep.services.runtime_captures import parse_trace


def trace(digest="a" * 64):
    common = {"timestamp": "2026-10-21T10:00:01Z", "pid": 123}
    return {
        "schema_version": 1,
        "input_sha256": digest,
        "source_run_id": "synthetic-run-1",
        "collector": {"name": "synthetic-test", "version": "1"},
        "environment": "emulator",
        "package_name": "org.example.fixture",
        "started_at": "2026-10-21T10:00:00Z",
        "ended_at": "2026-10-21T10:00:10Z",
        "collection_status": "partial",
        "coverage": {
            "process": "collected",
            "filesystem": "partial",
            "network": "collected",
            "sensitive_access": "not_collected",
        },
        "events": [
            {
                **common,
                "event_id": str(uuid4()),
                "kind": "process",
                "action": "start",
                "name": "org.example.fixture",
            },
            {
                **common,
                "event_id": str(uuid4()),
                "kind": "filesystem",
                "operation": "write",
                "path": "/data/user/0/org.example.fixture/files/demo",
            },
            {
                **common,
                "event_id": str(uuid4()),
                "kind": "network",
                "transport": "tcp",
                "destination_ip": "192.0.2.1",
                "destination_port": 443,
            },
        ],
    }


def base(case, sample):
    return f"/api/v1/cases/{case}/samples/{sample['id']}/runtime-captures"


def test_trace_schema_sensitive_events_and_empty_coverage():
    data = trace()
    data["coverage"]["sensitive_access"] = "partial"
    data["events"].append(
        {
            "event_id": str(uuid4()),
            "timestamp": "2026-10-21T10:00:02Z",
            "pid": 123,
            "kind": "sensitive_access",
            "resource": "location",
            "operation": "access",
        }
    )
    parsed = parse_trace(json.dumps(data).encode())
    assert parsed.events[-1].resource == "location"
    data["events"] = []
    assert not parse_trace(json.dumps(data).encode()).events


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_id",
        "out_of_order",
        "outside_interval",
        "naive_time",
        "negative_duration",
        "too_long",
        "not_collected",
        "port",
        "ip",
        "extra",
        "pid",
        "event_limit",
        "boolean_schema",
    ],
)
def test_invalid_chronology_coverage_and_event_fields_rejected(change):
    data = trace()
    if change == "duplicate_id":
        data["events"][1]["event_id"] = data["events"][0]["event_id"]
    elif change == "out_of_order":
        data["events"][0]["timestamp"] = "2026-10-21T10:00:02Z"
    elif change == "outside_interval":
        data["events"][0]["timestamp"] = "2026-10-21T09:59:59Z"
    elif change == "naive_time":
        data["started_at"] = "2026-10-21T10:00:00"
    elif change == "negative_duration":
        data["ended_at"] = "2026-10-20T10:00:00Z"
    elif change == "too_long":
        data["ended_at"] = "2026-10-23T10:00:00Z"
    elif change == "not_collected":
        data["coverage"]["network"] = "not_collected"
    elif change == "port":
        data["events"][2]["destination_port"] = 99999
    elif change == "ip":
        data["events"][2]["destination_ip"] = "example.org"
    elif change == "extra":
        data["events"][0]["command"] = "untrusted"
    elif change == "pid":
        data["events"][0]["pid"] = True
    elif change == "event_limit":
        data["events"] = [copy.deepcopy(data["events"][0])] * 2001
    else:
        data["schema_version"] = True
    with pytest.raises(HTTPException) as error:
        parse_trace(json.dumps(data).encode())
    assert error.value.status_code == 422


@pytest.mark.parametrize(
    "raw", [b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}', b"not JSON"]
)
def test_invalid_json_rejected(raw):
    with pytest.raises(HTTPException):
        parse_trace(raw)


def test_capture_api_raw_hash_summary_audit_and_migration(intake):
    client, app, config = intake
    case, sample = fixture_sample(client)
    command.downgrade(config, "0004_forensic_reports")
    command.upgrade(config, "head")
    raw = json.dumps(trace(sample["sha256"]), indent=2).encode()
    created = client.post(
        base(case, sample), content=raw, headers={"Content-Type": "application/json"}
    )
    assert created.status_code == 201, created.text
    capture = created.json()
    assert "artifact_key" not in capture
    assert capture["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
    assert capture["summary"]["event_counts"] == {
        "process": 1,
        "filesystem": 1,
        "network": 1,
        "sensitive_access": 0,
    }
    assert capture["summary"]["attribution"] == "collector_asserted_not_verified"
    assert capture["summary"]["isolation"] == "not_verified"
    uri = base(case, sample) + f"/{capture['id']}"
    response = client.get(uri + "/download")
    assert response.content == raw
    assert response.headers["x-capture-sha256"] == capture["artifact_sha256"]
    assert response.headers["cache-control"] == "no-store"
    assert client.get(uri).status_code == 200
    assert client.get(base(case, sample) + "?limit=1").json()["total"] == 1
    assert (
        client.post(
            base(case, sample), content=raw, headers={"Content-Type": "application/json"}
        ).status_code
        == 409
    )
    with app.state.sessions() as session:
        audit = session.scalar(select(AuditEvent).where(AuditEvent.subject_id == capture["id"]))
        assert audit.action == "runtime_capture.imported"
    command.check(config)


def test_capture_roles_and_case_scope(intake):
    client, _, _ = intake
    case, sample = fixture_sample(client)
    captured = client.post(base(case, sample), json=trace(sample["sha256"])).json()
    user = create_user(intake[1].state.sessions, "runtimeviewer", "runtime-viewer-password")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "runtime-viewer-password"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    uri = base(case, sample) + f"/{captured['id']}/download"
    assert client.get(uri, headers=headers).status_code == 404
    assert (
        client.put(
            f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"}
        ).status_code
        == 200
    )
    assert client.get(uri, headers=headers).status_code == 200
    assert (
        client.post(base(case, sample), json=trace(sample["sha256"]), headers=headers).status_code
        == 403
    )
    assert (
        client.put(
            f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "analyst"}
        ).status_code
        == 200
    )
    assert (
        client.post(base(case, sample), json=trace(sample["sha256"]), headers=headers).status_code
        == 201
    )
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(base(other, sample)).status_code == 404
    client.headers.pop("Authorization")
    assert client.get(uri).status_code == 401


def test_capture_type_size_hash_and_original_integrity(intake):
    client, app, _ = intake
    case, sample = fixture_sample(client)
    assert (
        client.post(
            base(case, sample), content=b"{}", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert client.post(base(case, sample), json=trace()).status_code == 409
    app.state.settings.max_runtime_capture_bytes = 1024
    assert (
        client.post(
            base(case, sample), content=b" " * 1025, headers={"Content-Type": "application/json"}
        ).status_code
        == 413
    )
    app.state.settings.max_runtime_capture_bytes = 2097152
    with app.state.sessions() as session:
        original = session.get(Sample, sample["id"])
        (app.state.settings.evidence_root / original.storage_key).write_bytes(b"changed")
    assert client.post(base(case, sample), json=trace(sample["sha256"])).status_code == 409
    assert client.get(base(case, sample)).json()["total"] == 0


@pytest.mark.parametrize("change", ["tampered", "missing", "size"])
def test_capture_download_integrity_failures(intake, change):
    client, app, _ = intake
    case, sample = fixture_sample(client)
    capture = client.post(base(case, sample), json=trace(sample["sha256"])).json()
    with app.state.sessions.begin() as session:
        stored = session.get(RuntimeCapture, capture["id"])
        path = app.state.settings.evidence_root / stored.artifact_key
        if change == "tampered":
            path.write_bytes(b"changed")
        elif change == "missing":
            path.unlink()
        else:
            stored.size_bytes += 1
    assert client.get(base(case, sample) + f"/{capture['id']}/download").status_code == 409


def test_capture_transaction_failure_cleans_artifact(intake):
    client, app, _ = intake
    case, sample = fixture_sample(client)

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("INSERT INTO RUNTIME_CAPTURES"):
            raise SQLAlchemyError("Injected failure")

    event.listen(app.state.engine, "before_cursor_execute", fail)
    try:
        assert client.post(base(case, sample), json=trace(sample["sha256"])).status_code == 503
    finally:
        event.remove(app.state.engine, "before_cursor_execute", fail)
    assert not list(app.state.settings.evidence_root.glob("runtime-captures/*.json"))
    assert client.get(base(case, sample)).json()["total"] == 0
    with app.state.sessions() as session:
        assert not session.scalars(
            select(AuditEvent).where(AuditEvent.action == "runtime_capture.imported")
        ).all()


def test_capture_id_collision_preserves_existing_file(intake, monkeypatch):
    client, app, _ = intake
    case, sample = fixture_sample(client)
    captured = client.post(base(case, sample), json=trace(sample["sha256"])).json()
    uri = base(case, sample) + f"/{captured['id']}/download"
    original = client.get(uri).content
    monkeypatch.setattr("godeep.services.runtime_captures.new_id", lambda: captured["id"])
    assert client.post(base(case, sample), json=trace(sample["sha256"])).status_code == 409
    assert client.get(uri).content == original
