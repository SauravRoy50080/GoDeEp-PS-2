"""Passive report rendering, bounded exports and verified case-scoped downloads."""

import hashlib
import json
from html.parser import HTMLParser
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from test_reports import base, completed

from godeep.persistence.models import ForensicReport
from godeep.services.auth import create_user
from godeep.services.report_html import render


def snapshot(schema=1):
    report = SimpleNamespace(
        id=str(uuid4()),
        schema_version=schema,
        input_sha256="a" * 64,
        artifact_sha256="b" * 64,
        case_id=str(uuid4()),
        sample_id=str(uuid4()),
    )
    document = {
        "schema_version": schema,
        "report_id": report.id,
        "report_type": "investigation_analysis_snapshot",
        "case": {"id": report.case_id},
        "sample": {"id": report.sample_id, "sha256": report.input_sha256},
        "analyses": [{"adapter": "example", "data": {"coverage": "partial"}}],
        "limitations": ["Synthetic limitations"],
        "selection": {"analysis_count": 1},
    }
    return report, document


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize("schema", [1, 2])
def test_passive_deterministic_complete_render(schema):
    report, document = snapshot(schema)
    hostile = '</pre><script>alert(1)</script><img src="https://example.test/x">&雪'
    document["case"]["name"] = hostile + "\ud800"
    document["extension"] = {"new": hostile}
    if schema == 2:
        document["runtime_captures"] = [{"capture_id": "source", "data": {"event": hostile}}]
    raw = json.dumps(document).encode()
    html = render(raw, report, 100000)
    assert html == render(raw, report, 100000)
    parser = Elements()
    parser.feed(html.decode())
    assert not {"script", "img", "a", "iframe", "form", "link"} & {tag for tag, _ in parser.tags}
    assert all(not key.startswith("on") for _, attrs in parser.tags for key in attrs)
    assert b"&lt;script&gt;" in html and b"partial" in html
    assert b"\\ud800" in html
    assert report.artifact_sha256.encode() in html
    assert b"Snapshot extensions" in html and b"collector assertions" in html
    if schema == 2:
        assert b"Runtime source 1" in html


@pytest.mark.parametrize("mode", ["id", "sample", "case", "schema", "json", "sources", "nan"])
def test_invalid_snapshot_is_rejected(mode):
    report, document = snapshot()
    if mode == "id":
        document["report_id"] = str(uuid4())
    elif mode == "sample":
        document["sample"]["sha256"] = "c" * 64
    elif mode == "case":
        document["case"]["id"] = str(uuid4())
    elif mode == "schema":
        document["schema_version"] = 3
        report.schema_version = 3
    elif mode == "sources":
        document["analyses"] = []
    elif mode == "nan":
        document["analyses"][0]["data"] = float("nan")
    raw = b"invalid" if mode == "json" else json.dumps(document).encode()
    with pytest.raises(HTTPException) as error:
        render(raw, report, 100000)
    assert error.value.status_code == 409


def test_exact_byte_budget_no_truncation():
    report, document = snapshot()
    raw = json.dumps(document).encode()
    rendered = render(raw, report, 100000)
    assert render(raw, report, len(rendered)) == rendered
    with pytest.raises(HTTPException) as error:
        render(raw, report, len(rendered) - 1)
    assert error.value.status_code == 413


def test_verified_download_headers_integrity_and_no_mutation(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)
    report = client.post(base(case, sample), json={"job_ids": [job["id"]]}).json()
    url = base(case, sample) + f"/{report['id']}"
    original = client.get(url + "/download").content
    response = client.get(url + "/export/html")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-source-report-sha256"] == hashlib.sha256(original).hexdigest()
    assert response.headers["x-export-sha256"] == hashlib.sha256(response.content).hexdigest()
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["content-disposition"].endswith('.html"')
    assert client.get(url + "/export/html").content == response.content
    assert client.get(url + "/download").content == original
    assert client.get(base(case, sample)).json()["total"] == 1
    app.state.settings.max_report_html_bytes = 1024
    assert client.get(url + "/export/html").status_code == 413
    app.state.settings.max_report_html_bytes = 67108864
    with app.state.sessions() as session:
        saved = session.get(ForensicReport, report["id"])
        (app.state.settings.evidence_root / saved.artifact_key).write_bytes(b"tampered")
    assert client.get(url + "/export/html").status_code == 409


def test_export_authorization_and_case_scope(intake):
    client, app, _ = intake
    case, sample, job = completed(intake)
    report = client.post(base(case, sample), json={"job_ids": [job["id"]]}).json()
    url = base(case, sample) + f"/{report['id']}/export/html"
    user = create_user(app.state.sessions, "htmlviewer", "html-viewer-test-password")
    token = client.post(
        "/api/v1/auth/login",
        json={
            "username": user.username,
            "password": "html-viewer-test-password",
        },
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert client.get(url, headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.get(url, headers=headers).status_code == 200
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(base(other, sample) + f"/{report['id']}/export/html").status_code == 404
    client.headers.pop("Authorization")
    assert client.get(url).status_code == 401
