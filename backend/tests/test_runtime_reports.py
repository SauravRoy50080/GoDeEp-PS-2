"""Versioned forensic snapshots preserve imported runtime provenance and gaps."""

import hashlib
import json
from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError
from test_jobs import fixture_sample, queue
from test_runtime_captures import trace

from godeep.persistence.models import AuditEvent, RuntimeCapture
from godeep.workers.runner import run_once


def setup(intake):
    client, _, _ = intake
    case, sample = fixture_sample(client)
    capture = client.post(
        f"/api/v1/cases/{case}/samples/{sample['id']}/runtime-captures",
        json=trace(sample["sha256"]),
    )
    assert capture.status_code == 201, capture.text
    uri = f"/api/v1/cases/{case}/samples/{sample['id']}/reports"
    return case, sample, capture.json(), uri


def snapshot(client, uri, selection):
    report = client.post(uri, json=selection)
    assert report.status_code == 201, report.text
    download = uri + f"/{report.json()['id']}/download"
    response = client.get(download)
    assert response.status_code == 200
    return report.json(), response.json(), download


def test_runtime_only_snapshot_schema_provenance_and_audit(intake):
    client, app, _ = intake
    _, sample, capture, uri = setup(intake)
    metadata, document, _ = snapshot(client, uri, {"capture_ids": [capture["id"]]})
    assert metadata["schema_version"] == document["schema_version"] == 2
    assert metadata["source_job_ids"] == [] and document["analyses"] == []
    assert document["selection"]["source_capture_ids"] == [capture["id"]]
    assert document["selection"]["runtime_capture_count"] == 1
    source = document["runtime_captures"][0]
    assert source["artifact_sha256"] == capture["artifact_sha256"]
    assert source["data"]["input_sha256"] == sample["sha256"]
    assert source["data"]["coverage"]["sensitive_access"] == "not_collected"
    assert source["data"]["collection_status"] == "partial"
    assert source["attribution"] == "collector_asserted_not_verified"
    assert source["isolation"] == "not_verified"
    assert "malware_verdict" not in document
    with app.state.sessions() as session:
        audit = session.scalar(select(AuditEvent).where(AuditEvent.subject_id == metadata["id"]))
        assert audit.details["source_capture_ids"] == [capture["id"]]


def test_combined_report_and_unchanged_static_only_v1(intake):
    client, app, _ = intake
    case, sample, capture, uri = setup(intake)
    job = queue(client, case, sample)
    run_once(app.state.sessions, app.state.settings)
    meta, static, _ = snapshot(client, uri, {"job_ids": [job["id"]]})
    assert meta["schema_version"] == 1 and "runtime_captures" not in static
    assert "source_capture_ids" not in static["selection"]
    _, combined, _ = snapshot(client, uri, {"job_ids": [job["id"]], "capture_ids": [capture["id"]]})
    assert combined["selection"]["analysis_count"] == 1
    assert combined["analyses"][0]["job_id"] == job["id"]
    assert combined["runtime_captures"][0]["capture_id"] == capture["id"]


@pytest.mark.parametrize(
    "selection",
    [
        {},
        {"job_ids": [], "capture_ids": []},
        {"capture_ids": [str(uuid4())] * 2},
        {"capture_ids": [str(uuid4()) for _ in range(20)], "job_ids": [str(uuid4())]},
    ],
)
def test_empty_duplicate_and_combined_source_limits(intake, selection):
    client, _, _ = intake
    _, _, _, uri = setup(intake)
    assert client.post(uri, json=selection).status_code == 422


@pytest.mark.parametrize(
    "change", ["tampered", "missing", "size", "input_identity", "invalid_schema"]
)
def test_source_integrity_or_structure_rejected(intake, change):
    client, app, _ = intake
    _, _, capture, uri = setup(intake)
    with app.state.sessions.begin() as session:
        source = session.get(RuntimeCapture, capture["id"])
        path = app.state.settings.evidence_root / source.artifact_key
        if change == "tampered":
            path.write_bytes(b"altered")
        elif change == "missing":
            path.unlink()
        elif change == "size":
            source.size_bytes += 1
        elif change == "input_identity":
            source.input_sha256 = "0" * 64
        else:
            document = json.loads(path.read_bytes())
            document["events"][0]["pid"] = -1
            raw = json.dumps(document).encode()
            path.write_bytes(raw)
            source.artifact_sha256 = hashlib.sha256(raw).hexdigest()
            source.size_bytes = len(raw)
    assert client.post(uri, json={"capture_ids": [capture["id"]]}).status_code == 409
    assert client.get(uri).json()["total"] == 0


def test_snapshot_independent_of_later_source_loss_and_metadata_summary(intake):
    client, app, _ = intake
    _, _, capture, uri = setup(intake)
    with app.state.sessions.begin() as session:
        stored = session.get(RuntimeCapture, capture["id"])
        stored.summary = {"collection_status": "completed"}
    _, document, download = snapshot(client, uri, {"capture_ids": [capture["id"]]})
    assert document["runtime_captures"][0]["data"]["collection_status"] == "partial"
    original = client.get(download).content
    with app.state.sessions() as session:
        source = session.get(RuntimeCapture, capture["id"])
        (app.state.settings.evidence_root / source.artifact_key).unlink()
    assert client.get(download).content == original
    assert client.post(uri, json={"capture_ids": [capture["id"]]}).status_code == 409


def test_other_sample_and_case_captures_rejected(intake):
    client, _, _ = intake
    _, _, capture, _ = setup(intake)
    other_case, other_sample = fixture_sample(client)
    other_uri = f"/api/v1/cases/{other_case}/samples/{other_sample['id']}/reports"
    assert client.post(other_uri, json={"capture_ids": [capture["id"]]}).status_code == 404
    assert client.post(other_uri, json={"capture_ids": [str(uuid4())]}).status_code == 404


def test_failed_collection_retained_and_report_bounds(intake):
    client, app, _ = intake
    case, sample, capture, uri = setup(intake)
    payload = trace(sample["sha256"])
    payload.update(collection_status="failed", source_run_id="failed-collector", events=[])
    failed = client.post(
        f"/api/v1/cases/{case}/samples/{sample['id']}/runtime-captures", json=payload
    ).json()
    _, document, _ = snapshot(client, uri, {"capture_ids": [failed["id"]]})
    assert document["runtime_captures"][0]["data"]["collection_status"] == "failed"
    app.state.settings.max_report_bytes = 1024
    assert client.post(uri, json={"capture_ids": [capture["id"]]}).status_code == 413


def test_report_transaction_failure_cleans_combined_snapshot(intake):
    client, app, _ = intake
    _, _, capture, uri = setup(intake)

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("INSERT INTO FORENSIC_REPORTS"):
            raise SQLAlchemyError("Injected failure")

    event.listen(app.state.engine, "before_cursor_execute", fail)
    try:
        assert client.post(uri, json={"capture_ids": [capture["id"]]}).status_code == 503
    finally:
        event.remove(app.state.engine, "before_cursor_execute", fail)
    assert not list(app.state.settings.evidence_root.glob("reports/*.json"))
    assert client.get(uri).json()["total"] == 0
