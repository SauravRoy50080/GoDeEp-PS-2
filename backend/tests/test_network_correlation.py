"""Exact IP matching, source claims, bounded evidence and snapshot authorization."""

import copy
import hashlib
import io
import json
from uuid import uuid4
from zipfile import ZipFile

import pytest
from android_fixtures import MANIFEST, binary_manifest
from fastapi import HTTPException
from sqlalchemy import func, select
from test_dex_calls import code_fixture
from test_runtime_captures import trace

from godeep.core.config import Settings
from godeep.persistence.models import AnalysisJob, AuditEvent, ForensicReport
from godeep.services.auth import create_user
from godeep.services.network_correlation import correlate
from godeep.workers.runner import run_once


def document():
    data = trace()
    event = data["events"][-1]
    event["destination_ip"] = "2001:db8::1"
    second = copy.deepcopy(event)
    second.update(event_id=str(uuid4()), destination_ip="192.0.2.2", destination_port=80)
    data["events"].append(second)
    return {
        "report_id": "example",
        "case": {"id": "case"},
        "sample": {"id": "sample", "sha256": data["input_sha256"]},
        "analyses": [
            {
                "job_id": "static-job",
                "adapter": "threat_review",
                "adapter_version": "1.0.0",
                "result_sha256": "b" * 64,
                "data": {
                    "schema_version": 1,
                    "adapter": "threat_review",
                    "adapter_version": "1.0.0",
                    "input_sha256": data["input_sha256"],
                    "coverage": {"dex": "partial"},
                    "dex": {
                        "dex_files": [
                            {
                                "network_candidates": [
                                    {
                                        "kind": "ip",
                                        "value": "2001:0db8:0:0:0:0:0:1",
                                        "byte_offset": 123,
                                    },
                                    {"kind": "ip", "value": "192.0.2.1"},
                                    {"kind": "domain", "value": "example.org"},
                                    {"kind": "url", "value": "https://example.org"},
                                ]
                            }
                        ]
                    },
                    "resources": {"network_candidates": [{"kind": "ip", "value": "192.0.2.1"}]},
                },
            }
        ],
        "runtime_captures": [
            {
                "capture_id": "capture",
                "artifact_sha256": "c" * 64,
                "source_run_id": data["source_run_id"],
                "data": data,
            }
        ],
    }


def test_canonical_matching_provenance_pagination_and_coverage():
    doc = document()
    result = correlate(doc, Settings(_env_file=None), 100, 0)
    assert result["summary"] == {
        "in_both_selected_sources": 1,
        "static_only_in_selection": 1,
        "collector_only_in_selection": 1,
    }
    assert [item["ip"] for item in result["items"]] == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
    assert result["items"][0]["static_count"] == 2
    item = result["items"][2]
    assert item["relationship"] == "in_both_selected_sources"
    assert item["static_evidence"][0]["snapshot_pointer"].endswith("/network_candidates/0")
    assert (
        item["collector_evidence"][0]["event_id"]
        == doc["runtime_captures"][0]["data"]["events"][2]["event_id"]
    )
    assert item["collector_evidence"][0]["destination_port"] == 443
    assert result["sources"][0]["source_coverage"] == {"dex": "partial"}
    assert result["non_ip_candidates_skipped"] == 2
    assert correlate(doc, Settings(_env_file=None), 1, 1)["items"] == result["items"][1:2]
    assert correlate(doc, Settings(_env_file=None), 1, 100)["items"] == []
    assert "risk_score" not in result


def test_limits_counts_and_duplicate_claims_are_not_votes():
    doc = document()
    doc["runtime_captures"].append(copy.deepcopy(doc["runtime_captures"][0]))
    doc["runtime_captures"][1]["capture_id"] = "another-capture"
    settings = Settings(_env_file=None, max_network_correlation_evidence=1)
    result = correlate(doc, settings, 100, 0)
    assert result["evidence_limited"]
    assert result["items"][0]["static_count"] == 2
    assert len(result["items"][0]["static_evidence"]) == 1
    assert result["items"][2]["collector_count"] == 2
    for name in ("max_network_correlation_groups", "max_network_correlation_candidates"):
        with pytest.raises(HTTPException) as error:
            correlate(doc, Settings(_env_file=None, **{name: 1}), 100, 0)
        assert error.value.status_code == 413


def test_no_dns_no_ipv4_mapped_merging_scoped_exclusion_and_empty_selection():
    doc = document()
    candidates = doc["analyses"][0]["data"]["dex"]["dex_files"][0]["network_candidates"]
    candidates[:] = [
        {"kind": "domain", "value": "example.org"},
        {"kind": "ip", "value": "bad"},
        {"kind": "ip", "value": "fe80::1%eth0"},
        {"kind": "ip", "value": "::ffff:192.0.2.2"},
    ]
    doc["analyses"][0]["data"]["resources"]["network_candidates"] = []
    result = correlate(doc, Settings(_env_file=None), 100, 0)
    assert result["summary"]["in_both_selected_sources"] == 0
    assert result["invalid_or_scoped_ips_skipped"] == 2
    assert result["total"] == 3
    candidates.clear()
    doc["runtime_captures"][0]["data"]["events"] = []
    result = correlate(doc, Settings(_env_file=None), 100, 0)
    assert result["items"] == [] and result["total"] == 0


@pytest.mark.parametrize("side", ["static", "runtime", "unsupported"])
def test_required_supported_sources(side):
    doc = document()
    if side == "static":
        doc["analyses"] = []
    elif side == "runtime":
        doc["runtime_captures"] = []
    else:
        doc["analyses"][0]["adapter_version"] = "999.0.0"
    with pytest.raises(HTTPException) as error:
        correlate(doc, Settings(_env_file=None), 100, 0)
    assert error.value.status_code == 409


def setup(intake):
    client, app, _ = intake
    case = client.post("/api/v1/cases", json={"name": "IP correlation"}).json()["id"]
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest(MANIFEST))
        archive.writestr("classes.dex", code_fixture()[0])
        archive.writestr("assets/config.json", '{"url":"https://192.0.2.1/path"}')
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=buffer.getvalue(),
        headers={
            "X-Filename": "correlation.apk",
            "Content-Type": "application/octet-stream",
        },
    ).json()
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={
            "sample_id": sample["id"],
            "adapter": "threat_review",
        },
    ).json()
    assert run_once(app.state.sessions, app.state.settings)
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}"
    capture = client.post(prefix + "/runtime-captures", json=trace(sample["sha256"])).json()
    report = client.post(
        prefix + "/reports",
        json={
            "job_ids": [job["id"]],
            "capture_ids": [capture["id"]],
        },
    )
    assert report.status_code == 201, report.text
    uri = prefix + f"/reports/{report.json()['id']}"
    return case, sample, job, report.json(), uri


def test_actual_worker_capture_report_correlation_no_mutation_and_historical_snapshot(intake):
    client, app, _ = intake
    _, _, job, report, uri = setup(intake)
    original = client.get(uri + "/download").content
    with app.state.sessions() as session:
        before = session.scalar(select(func.count()).select_from(AuditEvent))
        source = session.get(AnalysisJob, job["id"])
        (app.state.settings.evidence_root / source.result_key).unlink()
    response = client.get(uri + "/network-correlation")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["source_report_sha256"] == hashlib.sha256(original).hexdigest()
    item = next(item for item in result["items"] if item["ip"] == "192.0.2.1")
    assert item["relationship"] == "in_both_selected_sources"
    assert response.headers["cache-control"] == "no-store"
    assert (
        client.get(uri + "/network-correlation?limit=1&offset=0").json()["total"] == result["total"]
    )
    assert client.get(uri + "/download").content == original
    with app.state.sessions() as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == before
        assert session.scalar(select(func.count()).select_from(ForensicReport)) == 1


@pytest.mark.parametrize("mode", ["tamper", "metadata", "output_bound", "groups", "pending_schema"])
def test_integrity_identity_and_output_budget(intake, mode):
    client, app, _ = intake
    _, _, _, report, uri = setup(intake)
    if mode in {"tamper", "metadata", "pending_schema"}:
        with app.state.sessions.begin() as session:
            saved = session.get(ForensicReport, report["id"])
            if mode == "tamper":
                (app.state.settings.evidence_root / saved.artifact_key).write_bytes(b"changed")
            elif mode == "metadata":
                saved.input_sha256 = "d" * 64
            else:
                saved.schema_version = 1
    elif mode == "groups":
        app.state.settings.max_network_correlation_candidates = 1
    else:
        app.state.settings.max_network_correlation_bytes = 1024
    assert client.get(uri + "/network-correlation").status_code == (
        413 if mode in {"output_bound", "groups"} else 409
    )


def test_permissions_case_scope_and_query_bounds(intake):
    client, app, _ = intake
    case, sample, _, _, uri = setup(intake)
    user = create_user(app.state.sessions, "networkviewer", "network-viewer-password")
    token = client.post(
        "/api/v1/auth/login",
        json={
            "username": user.username,
            "password": "network-viewer-password",
        },
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert client.get(uri + "/network-correlation", headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.get(uri + "/network-correlation", headers=headers).status_code == 200
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(uri.replace(case, other) + "/network-correlation").status_code == 404
    assert client.get(uri + "/network-correlation?limit=201").status_code == 422
    assert client.get(uri + "/network-correlation?offset=-1").status_code == 422
    assert (
        client.get(uri.replace(sample["id"], str(uuid4())) + "/network-correlation").status_code
        == 404
    )
    client.headers.pop("Authorization")
    assert client.get(uri + "/network-correlation").status_code == 401


@pytest.mark.parametrize("mode", ["analysis_identity", "trace_identity", "invalid_trace"])
def test_rehashed_but_invalid_source_identity_is_rejected(intake, mode):
    client, app, _ = intake
    _, _, _, report, uri = setup(intake)
    with app.state.sessions.begin() as session:
        saved = session.get(ForensicReport, report["id"])
        path = app.state.settings.evidence_root / saved.artifact_key
        snapshot = json.loads(path.read_bytes())
        if mode == "analysis_identity":
            snapshot["analyses"][0]["data"]["input_sha256"] = "d" * 64
        elif mode == "trace_identity":
            snapshot["runtime_captures"][0]["source_run_id"] = "wrong"
        else:
            snapshot["runtime_captures"][0]["data"]["events"][-1]["pid"] = -1
        raw = json.dumps(snapshot).encode()
        path.write_bytes(raw)
        saved.artifact_sha256 = hashlib.sha256(raw).hexdigest()
        saved.size_bytes = len(raw)
    assert client.get(uri + "/network-correlation").status_code == 409
