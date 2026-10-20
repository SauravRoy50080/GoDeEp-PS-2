"""Report integrity, authorization, selection and persistence through real APIs."""

import hashlib
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError
from test_jobs import fixture_sample, queue

from godeep.persistence.models import AnalysisJob, AuditEvent, ForensicReport, Sample
from godeep.services.auth import create_user
from godeep.workers.runner import run_once


def completed(intake):
    client, app, _ = intake
    case, sample = fixture_sample(client)
    job = queue(client, case, sample)
    run_once(app.state.sessions, app.state.settings)
    return case, sample, job


def base(case, sample):
    return f"/api/v1/cases/{case}/samples/{sample['id']}/reports"


def test_persisted_report_hash_provenance_and_migration_preservation(intake):
    client, app, config = intake
    case, sample, job = completed(intake)
    command.downgrade(config, "0003_analysis_jobs")
    command.upgrade(config, "head")
    response = client.post(base(case, sample), json={"job_ids": [job["id"]]})
    assert response.status_code == 201, response.text
    report = response.json()
    assert report["source_job_ids"] == [job["id"]] and "artifact_key" not in report
    download = client.get(base(case, sample) + f"/{report['id']}/download")
    assert download.status_code == 200
    assert download.headers["x-report-sha256"] == hashlib.sha256(download.content).hexdigest()
    assert report["artifact_sha256"] == hashlib.sha256(download.content).hexdigest()
    assert download.headers["cache-control"] == "no-store"
    assert "attachment" in download.headers["content-disposition"]
    document = download.json()
    assert document["sample"]["sha256"] == sample["sha256"]
    assert document["analyses"][0]["data"]["adapter"] == "archive_inventory"
    assert document["selection"]["analysis_count"] == 1
    assert document["sample"]["original_verified_at"]
    assert "risk_score" not in document and "malware_verdict" not in document
    page = client.get(base(case, sample) + "?limit=1&offset=0").json()
    assert page["total"] == 1 and page["items"][0]["id"] == report["id"]
    with app.state.sessions() as session:
        audit = session.scalar(select(AuditEvent).where(AuditEvent.subject_id == report["id"]))
        assert (
            audit.action == "report.created"
            and audit.details["artifact_sha256"] == report["artifact_sha256"]
        )
    command.upgrade(config, "head")
    command.check(config)
    assert (
        client.get(base(case, sample) + f"/{report['id']}").json()["artifact_sha256"]
        == report["artifact_sha256"]
    )
    assert client.get(base(case, sample) + f"/{report['id']}/download").content == download.content


@pytest.mark.parametrize("mode", ["duplicate", "empty", "unknown", "pending", "another_sample"])
def test_invalid_selection_cannot_create_reports(intake, mode):
    client, app, _ = intake
    case, sample, job = completed(intake)
    job_ids = [job["id"]]
    expected = (
        422
        if mode in {"duplicate", "empty"}
        else 404
        if mode in {"unknown", "another_sample"}
        else 409
    )
    if mode == "duplicate":
        job_ids *= 2
    elif mode == "empty":
        job_ids = []
    elif mode == "unknown":
        job_ids = [str(uuid4())]
    elif mode == "pending":
        job_ids = [queue(client, case, sample)["id"]]
    else:
        with app.state.sessions() as session:
            saved = session.get(Sample, sample["id"])
            raw = (app.state.settings.evidence_root / saved.storage_key).read_bytes()
        other_sample = client.post(
            f"/api/v1/cases/{case}/samples",
            content=raw,
            headers={"X-Filename": "same.apk", "Content-Type": "application/octet-stream"},
        ).json()
        other = queue(client, case, other_sample)
        run_once(app.state.sessions, app.state.settings)
        job_ids = [other["id"]]
    response = client.post(base(case, sample), json={"job_ids": job_ids})
    assert response.status_code == expected, response.text
    assert client.get(base(case, sample)).json()["total"] == 0


@pytest.mark.parametrize("mode", ["original", "source", "missing_reference", "output_limit"])
def test_evidence_failures_and_output_bounds_leave_no_report(intake, mode):
    client, app, _ = intake
    case, sample, job = completed(intake)
    with app.state.sessions() as session:
        source = session.get(AnalysisJob, job["id"])
        saved = session.get(Sample, sample["id"])
        if mode == "original":
            (app.state.settings.evidence_root / saved.storage_key).write_bytes(b"changed")
        elif mode == "source":
            (app.state.settings.evidence_root / source.result_key).write_bytes(b"changed")
    if mode == "missing_reference":
        with app.state.sessions.begin() as session:
            session.get(AnalysisJob, job["id"]).result_key = None
        assert client.get(f"/api/v1/cases/{case}/analyses/{job['id']}/result").status_code == 409
    if mode == "output_limit":
        app.state.settings.max_report_bytes = 1024
    response = client.post(base(case, sample), json={"job_ids": [job["id"]]})
    assert response.status_code == (413 if mode == "output_limit" else 409), response.text
    assert client.get(base(case, sample)).json()["total"] == 0
    assert not list(app.state.settings.evidence_root.glob("reports/*.json"))


def test_report_tampering_and_original_change_after_snapshot(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)
    report = client.post(base(case, sample), json={"job_ids": [job["id"]]}).json()
    path = base(case, sample) + f"/{report['id']}/download"
    original_report = client.get(path).content
    with app.state.sessions() as session:
        saved = session.get(Sample, sample["id"])
        artifact = session.get(ForensicReport, report["id"])
        (app.state.settings.evidence_root / saved.storage_key).write_bytes(b"later change")
        report_file = app.state.settings.evidence_root / artifact.artifact_key
    # Existing snapshot remains readable; new generation must recheck original bytes.
    assert client.get(path).content == original_report
    report_file.write_bytes(b"altered")
    assert client.get(path).status_code == 409
    report_file.unlink()
    assert client.get(path).status_code == 409


def test_report_permissions_and_case_scope(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)
    report = client.post(base(case, sample), json={"job_ids": [job["id"]]}).json()
    user = create_user(app.state.sessions, "reportviewer", "report-viewer-test-password")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "report-viewer-test-password"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    download = base(case, sample) + f"/{report['id']}/download"
    assert client.get(download, headers=headers).status_code == 404
    assert (
        client.put(
            f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"}
        ).status_code
        == 200
    )
    assert client.get(download, headers=headers).status_code == 200
    assert client.get(base(case, sample), headers=headers).status_code == 200
    assert (
        client.post(base(case, sample), json={"job_ids": [job["id"]]}, headers=headers).status_code
        == 403
    )
    other = client.post("/api/v1/cases", json={"name": "Other case"}).json()["id"]
    assert client.get(base(other, sample) + f"/{report['id']}/download").status_code == 404
    client.headers.pop("Authorization")
    assert client.get(download).status_code == 401


def test_failed_report_transaction_cleans_artifact_and_audit(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)

    def fail(connection, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith("INSERT INTO FORENSIC_REPORTS"):
            raise SQLAlchemyError("Injected database failure")

    event.listen(app.state.engine, "before_cursor_execute", fail)
    try:
        response = client.post(base(case, sample), json={"job_ids": [job["id"]]})
        assert response.status_code == 503
        assert "Injected" not in response.text
    finally:
        event.remove(app.state.engine, "before_cursor_execute", fail)
    assert client.get(base(case, sample)).json()["total"] == 0
    assert not list(app.state.settings.evidence_root.glob("reports/*.json"))
    with app.state.sessions() as session:
        assert not session.scalars(
            select(AuditEvent).where(AuditEvent.action == "report.created")
        ).all()


def test_completed_job_with_unavailable_phase_stays_unavailable_in_report(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)
    app.state.settings.signer_java_path = None
    app.state.settings.signer_jar_path = None
    app.state.settings.signer_jar_sha256 = None
    verifier = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample["id"], "adapter": "signature_verify"},
    ).json()
    run_once(app.state.sessions, app.state.settings)
    report = client.post(base(case, sample), json={"job_ids": [job["id"], verifier["id"]]}).json()
    document = client.get(base(case, sample) + f"/{report['id']}/download").json()
    assert document["selection"]["analysis_count"] == 2
    source = next(a for a in document["analyses"] if a["adapter"] == "signature_verify")
    assert source["data"]["coverage"] == "not_completed"
    assert source["data"]["signature_verification"]["status"] == "tool_unavailable"


def test_report_id_collision_does_not_delete_existing_artifact(intake, monkeypatch):
    from godeep.services import reports

    client, _, _ = intake
    case, sample, job = completed(intake)
    report = client.post(base(case, sample), json={"job_ids": [job["id"]]}).json()
    download = base(case, sample) + f"/{report['id']}/download"
    original = client.get(download).content
    monkeypatch.setattr(reports, "new_id", lambda: report["id"])
    assert client.post(base(case, sample), json={"job_ids": [job["id"]]}).status_code == 503
    assert client.get(download).content == original
    assert client.get(base(case, sample)).json()["total"] == 1
