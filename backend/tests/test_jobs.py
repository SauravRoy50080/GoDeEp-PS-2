"""Analysis queue, subprocess adapter, permissions and evidence-result integrity."""

import hashlib
import io
from datetime import timedelta
from uuid import uuid4
from zipfile import ZipFile

from sqlalchemy import select

from godeep.persistence.models import AnalysisJob, AuditEvent, Sample, utc_now
from godeep.services.auth import create_user
from godeep.services.jobs import claim_job, expire_jobs, finish_job
from godeep.workers.runner import run_once


def fixture_sample(client):
    case_id = client.post("/api/v1/cases", json={"name": "Analysis fixture"}).json()["id"]
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", "synthetic manifest")
        archive.writestr("classes.dex", "synthetic dex")
        archive.writestr("lib/arm64-v8a/libdemo.so", "synthetic library")
    sample = client.post(
        f"/api/v1/cases/{case_id}/samples",
        content=buffer.getvalue(),
        headers={"X-Filename": "fixture.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201
    return case_id, sample.json()


def queue(client, case_id, sample):
    response = client.post(f"/api/v1/cases/{case_id}/analyses", json={"sample_id": sample["id"]})
    assert response.status_code == 202, response.text
    return response.json()


def path(case_id, job_id):
    return f"/api/v1/cases/{case_id}/analyses/{job_id}"


def test_full_subprocess_pipeline_and_result_provenance(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    assert job["status"] == "queued" and job["attempt"] == 1
    assert job["input_sha256"] == sample["sha256"]
    assert "claim_token" not in job and "result_key" not in job
    assert client.get(path(case_id, job["id"]) + "/result").status_code == 409
    assert run_once(app.state.sessions, app.state.settings)
    completed = client.get(path(case_id, job["id"])).json()
    assert completed["status"] == "completed", completed
    assert completed["started_at"].endswith("Z") and completed["finished_at"].endswith("Z")
    result = client.get(path(case_id, job["id"]) + "/result")
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["observations"]["dex_count"] == 1
    assert data["observations"]["native_library_count"] == 1
    assert data["observations"]["manifest_present"] is True
    assert "risk_score" not in data
    with app.state.sessions() as session:
        stored = session.get(AnalysisJob, job["id"])
        artifact = app.state.settings.evidence_root / stored.result_key
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == completed["result_sha256"]
        events = session.scalars(select(AuditEvent).where(AuditEvent.subject_id == job["id"])).all()
        assert {e.action for e in events} == {
            "analysis.queued",
            "analysis.started",
            "analysis.completed",
        }
    assert not run_once(app.state.sessions, app.state.settings)
    assert not list((app.state.settings.evidence_root / "worker-staging").iterdir())


def test_cancel_and_explicit_retry_preserve_history_and_limit(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    first = queue(client, case_id, sample)
    current = first
    for attempt in range(1, 4):
        current_path = path(case_id, current["id"])
        assert client.post(current_path + "/cancel").json()["status"] == "cancelled"
        assert client.post(current_path + "/cancel").status_code == 200
        response = client.post(current_path + "/retry")
        if attempt == 3:
            assert response.status_code == 409
        else:
            assert response.status_code == 202
            assert client.post(current_path + "/retry").status_code == 409
            retry = response.json()
            assert retry["parent_id"] == current["id"] and retry["attempt"] == attempt + 1
            current = retry
    assert not run_once(app.state.sessions, app.state.settings)
    assert client.get(f"/api/v1/cases/{case_id}/analyses?limit=1").json()["total"] == 3


def test_running_cancel_and_stale_completion_are_rejected(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    claimed = claim_job(app.state.sessions)
    assert claimed.id == job["id"] and claimed.status == "running"
    assert not finish_job(app.state.sessions, claimed.id, str(uuid4()), error_code="wrong_token")
    assert client.post(path(case_id, claimed.id) + "/cancel").status_code == 200
    assert not finish_job(app.state.sessions, claimed.id, claimed.claim_token, error_code="late")


def test_abandoned_job_lease_expires_with_audit(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    queued = queue(client, case_id, sample)
    claimed = claim_job(app.state.sessions)
    with app.state.sessions.begin() as session:
        session.get(AnalysisJob, claimed.id).lease_expires_at = utc_now() - timedelta(seconds=1)
    assert expire_jobs(app.state.sessions) == 1
    assert expire_jobs(app.state.sessions) == 0
    failed = client.get(path(case_id, queued["id"])).json()
    assert failed["status"] == "failed" and failed["error_code"] == "worker_lease_expired"
    assert not finish_job(app.state.sessions, claimed.id, claimed.claim_token, error_code="late")


def test_original_tampering_fails_analysis(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    with app.state.sessions() as session:
        stored = session.get(Sample, sample["id"])
        (app.state.settings.evidence_root / stored.storage_key).write_bytes(b"tampered")
    assert run_once(app.state.sessions, app.state.settings)
    failed = client.get(path(case_id, job["id"])).json()
    assert failed["status"] == "failed"
    assert failed["error_code"] == "input_integrity_mismatch"
    assert failed["result_sha256"] is None


def test_result_tampering_is_not_returned(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    run_once(app.state.sessions, app.state.settings)
    with app.state.sessions() as session:
        stored = session.get(AnalysisJob, job["id"])
        (app.state.settings.evidence_root / stored.result_key).write_text("{}", encoding="utf-8")
    assert client.get(path(case_id, job["id"]) + "/result").status_code == 409
    assert client.post(path(case_id, job["id"]) + "/retry").status_code == 409
    assert client.post(path(case_id, job["id"]) + "/cancel").status_code == 409


def test_readonly_and_outsider_permissions_cover_jobs(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    user = create_user(app.state.sessions, "jobviewer", "viewer-test-password-123")
    raw = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "viewer-test-password-123"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + raw}
    base = f"/api/v1/cases/{case_id}/analyses"
    assert client.get(base, headers=headers).status_code == 404
    assert client.get(path(case_id, job["id"]), headers=headers).status_code == 404
    assert client.post(base, headers=headers, json={"sample_id": sample["id"]}).status_code == 404
    client.put(f"/api/v1/cases/{case_id}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.get(base, headers=headers).status_code == 200
    assert client.get(path(case_id, job["id"]), headers=headers).status_code == 200
    assert client.post(base, headers=headers, json={"sample_id": sample["id"]}).status_code == 403
    assert client.post(path(case_id, job["id"]) + "/cancel", headers=headers).status_code == 403
    assert client.post(path(case_id, job["id"]) + "/retry", headers=headers).status_code == 403
    run_once(app.state.sessions, app.state.settings)
    assert client.get(path(case_id, job["id"]) + "/result", headers=headers).status_code == 200
    client.headers.pop("Authorization")
    assert client.get(base).status_code == 401


def test_cross_case_sample_and_unregistered_adapter_rejected(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    base = f"/api/v1/cases/{other}/analyses"
    assert client.post(base, json={"sample_id": sample["id"]}).status_code == 404
    assert (
        client.post(base, json={"sample_id": sample["id"], "adapter": "shell"}).status_code == 422
    )
    job = queue(client, case_id, sample)
    assert client.get(path(other, job["id"])).status_code == 404
    with app.state.sessions.begin() as session:
        session.get(AnalysisJob, job["id"]).adapter_version = "not-installed"
    run_once(app.state.sessions, app.state.settings)
    assert (
        client.get(path(case_id, job["id"])).json()["error_code"] == "unsupported_adapter_version"
    )


def test_worker_timeout_kills_child_and_records_failure(intake, monkeypatch):
    import io

    from godeep.workers import runner

    client, app, _ = intake
    app.state.settings.job_timeout_seconds = 1
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)

    class SlowProcess:
        def __init__(self, *args, **kwargs):
            self.stdin = io.StringIO()
            self.killed = False

        def poll(self):
            return -1 if self.killed else None

        def kill(self):
            self.killed = True

        def wait(self, timeout):
            return -1

    with monkeypatch.context() as patch:
        patch.setattr(runner.subprocess, "Popen", SlowProcess)
        ticks = iter([0.0, 2.0])
        patch.setattr(runner.time, "monotonic", lambda: next(ticks))
        assert runner.run_once(app.state.sessions, app.state.settings)
    failed = client.get(path(case_id, job["id"])).json()
    assert failed["status"] == "failed" and failed["error_code"] == "adapter_timeout"
    assert not list((app.state.settings.evidence_root / "worker-staging").iterdir())


def test_oversized_result_and_missing_original_fail_explicitly(intake):
    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    app.state.settings.max_result_bytes = 1
    job = queue(client, case_id, sample)
    run_once(app.state.sessions, app.state.settings)
    assert client.get(path(case_id, job["id"])).json()["error_code"] == "invalid_adapter_output"
    app.state.settings.max_result_bytes = 1048576
    second = queue(client, case_id, sample)
    with app.state.sessions() as session:
        stored = session.get(Sample, sample["id"])
        (app.state.settings.evidence_root / stored.storage_key).unlink()
    run_once(app.state.sessions, app.state.settings)
    assert client.get(path(case_id, second["id"])).json()["error_code"] == "evidence_unavailable"


def test_worker_cli_once_uses_configured_database_and_store(intake, monkeypatch):
    import sys

    from godeep.workers import runner

    client, app, _ = intake
    case_id, sample = fixture_sample(client)
    job = queue(client, case_id, sample)
    monkeypatch.setenv("GODEEP_EVIDENCE_ROOT", str(app.state.settings.evidence_root))
    monkeypatch.setattr(sys, "argv", ["godeep.workers.runner", "--once"])
    runner.main()
    assert client.get(path(case_id, job["id"])).json()["status"] == "completed"
