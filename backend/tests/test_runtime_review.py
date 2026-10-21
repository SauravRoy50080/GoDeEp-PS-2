"""Runtime inventories, sparse activity, comparisons, provenance and access controls."""

import copy
import hashlib
import json
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select
from test_jobs import fixture_sample
from test_runtime_captures import trace

from godeep.core.config import Settings
from godeep.persistence.models import AuditEvent, ForensicReport, RuntimeCapture
from godeep.services.auth import create_user
from godeep.services.runtime_review import derive, render, validate


def full_trace(digest="a" * 64):
    data = trace(digest)
    data["coverage"]["sensitive_access"] = "partial"
    common = {"event_id": str(uuid4()), "timestamp": "2026-10-21T10:00:02Z", "pid": 123}
    data["events"].append(
        {**common, "kind": "sensitive_access", "resource": "location", "operation": "access"}
    )
    duplicate = copy.deepcopy(data["events"][0])
    duplicate.update(event_id=str(uuid4()), timestamp="2026-10-21T10:00:03Z", action="observed")
    data["events"].append(duplicate)
    return data


def source(data):
    return {
        "capture_id": str(uuid4()),
        "artifact_sha256": hashlib.sha256(json.dumps(data).encode()).hexdigest(),
        "source_run_id": data["source_run_id"],
        "representation": "validated_normalized_trace_v1",
        "attribution": "collector_asserted_not_verified",
        "isolation": "not_verified",
        "data": data,
    }


def document(*traces):
    return {
        "report_id": str(uuid4()),
        "case": {"id": str(uuid4())},
        "sample": {"id": str(uuid4()), "sha256": "a" * 64},
        "analyses": [],
        "runtime_captures": [source(data) for data in traces or (full_trace(),)],
    }


def view(doc, section="process", settings=None, **query):
    return derive(
        doc, validate(doc), settings or Settings(_env_file=None), section=section, **query
    )


def test_four_inventories_exact_identities_counts_and_evidence():
    doc = document()
    for kind, identity in [
        ("process", {"name": "org.example.fixture", "action": "start"}),
        (
            "filesystem",
            {
                "path": "/data/user/0/org.example.fixture/files/demo",
                "operation": "write",
                "content_sha256": None,
            },
        ),
        ("network", {"transport": "tcp", "destination_ip": "192.0.2.1", "destination_port": 443}),
        ("sensitive_access", {"resource": "location", "operation": "access"}),
    ]:
        result = view(doc, kind)
        item = next(item for item in result["items"] if item["identity"] == identity)
        assert item["count"] == 1
        evidence = item["evidence"][0]
        pointer_index = int(evidence["snapshot_pointer"].rsplit("/", 1)[1])
        original = doc["runtime_captures"][0]["data"]["events"][pointer_index]
        assert evidence["event_id"] == original["event_id"]
        assert evidence["pid"] == 123
        assert result["sources"][0]["coverage"] == doc["runtime_captures"][0]["data"]["coverage"]
        assert "risk_score" not in result
    assert {item["identity"]["action"] for item in view(doc)["items"]} == {"start", "observed"}


def test_exact_file_strings_hashes_and_sensitive_operations_stay_distinct():
    data = full_trace()
    file_event = data["events"][1]
    sensitive = data["events"][3]
    data["events"] = []
    for path, digest in [("/a/../b", None), ("/b", None), ("/b", "b" * 64)]:
        data["events"].append(
            {**file_event, "path": path, "content_sha256": digest, "event_id": str(uuid4())}
        )
    for operation in ["access", "Access"]:
        data["events"].append({**sensitive, "operation": operation, "event_id": str(uuid4())})
    doc = document(data)
    assert view(doc, "filesystem")["total"] == 3
    assert view(doc, "sensitive_access")["total"] == 2


def test_network_canonicalization_ports_transports_and_no_dns_or_mapped_merging():
    data = full_trace()
    original = data["events"][2]
    data["events"] = []
    for ip, port, transport in [
        ("2001:0db8::1", 443, "tcp"),
        ("2001:db8::1", 443, "tcp"),
        ("2001:db8::1", 80, "tcp"),
        ("2001:db8::1", 443, "udp"),
        ("::ffff:192.0.2.1", 443, "tcp"),
        ("192.0.2.1", 443, "tcp"),
    ]:
        data["events"].append(
            {
                **original,
                "event_id": str(uuid4()),
                "destination_ip": ip,
                "destination_port": port,
                "transport": transport,
            }
        )
    result = view(document(data), "network")
    assert result["total"] == 5
    assert sorted(item["count"] for item in result["items"]) == [1, 1, 1, 1, 2]


def test_activity_half_open_boundary_sparse_buckets_and_capture_relative_clocks():
    a, b = full_trace(), full_trace()
    for data in [a, b]:
        data["events"] = [data["events"][0], copy.deepcopy(data["events"][0])]
        data["events"][0]["timestamp"] = "2026-10-21T10:00:00Z"
        data["events"][1].update(event_id=str(uuid4()), timestamp="2026-10-21T10:00:10Z")
    doc = document(a, b)
    result = view(doc, "activity", bucket_seconds=2)
    assert result["total"] == 4  # No fabricated empty bins at 2,4,6,8.
    assert [item["identity"]["elapsed_start_seconds"] for item in result["items"]] == [0, 10, 0, 10]
    assert all(item["count"] == 1 for item in result["items"])
    assert all(item["event_kind_counts"]["process"] == 1 for item in result["items"])
    assert result["bucket_seconds"] == 2


def test_comparison_exact_membership_counts_no_pid_join_and_no_absence_inference():
    a, b = full_trace(), full_trace()
    b["events"][0]["pid"] = 999
    b["events"][4]["action"] = "stop"
    doc = document(a, b)
    left, right = [entry["capture_id"] for entry in doc["runtime_captures"]]
    result = view(doc, left=left, right=right)
    assert result["comparison_summary"] == {
        "both_selected_captures": 1,
        "left_selection_only": 1,
        "right_selection_only": 1,
    }
    start = next(item for item in result["items"] if item["identity"]["action"] == "start")
    assert start["left_count"] == start["right_count"] == 1 and start["count_delta"] == 0
    assert {item["pid"] for item in start["evidence"]} == {123, 999}
    assert result["sources"][0]["coverage"]["filesystem"] == "partial"
    assert any("missing items" in text for text in result["limitations"])


def test_evidence_caps_preserve_counts_pagination_and_source_pointers():
    data = full_trace()
    data["events"] = [{**data["events"][0], "event_id": str(uuid4())} for _ in range(4)]
    doc = document(data)
    result = view(doc, settings=Settings(_env_file=None, max_runtime_review_evidence=1))
    assert result["matching_event_count"] == 4
    assert result["items"][0]["count"] == 4
    assert len(result["items"][0]["evidence"]) == 1 and result["evidence_limited"]
    doc = document()
    result = view(doc)
    assert view(doc, limit=1, offset=1)["items"] == result["items"][1:2]
    assert view(doc, offset=40000)["items"] == []
    capture_id = doc["runtime_captures"][0]["capture_id"]
    assert view(doc, capture_id=capture_id)["total"] == 2


@pytest.mark.parametrize("setting", ["max_runtime_review_events", "max_runtime_review_groups"])
def test_inventory_budgets_fail_explicitly(setting):
    with pytest.raises(HTTPException) as error:
        view(document(), settings=Settings(_env_file=None, **{setting: 1}))
    assert error.value.status_code == 413


def test_empty_failed_and_uncollected_coverage_remain_explicit():
    data = full_trace()
    data["events"] = []
    data["collection_status"] = "failed"
    data["coverage"] = dict.fromkeys(data["coverage"], "not_collected")
    result = view(document(data))
    assert result["items"] == [] and result["events_scanned"] == 0
    assert result["sources"][0]["collection_status"] == "failed"
    assert set(result["sources"][0]["coverage"].values()) == {"not_collected"}


def setup(intake):
    client, app, _ = intake
    case, sample = fixture_sample(client)
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}"
    captures = []
    for data in [full_trace(sample["sha256"]), full_trace(sample["sha256"])]:
        response = client.post(prefix + "/runtime-captures", json=data)
        assert response.status_code == 201, response.text
        captures.append(response.json()["id"])
    report = client.post(prefix + "/reports", json={"capture_ids": captures})
    assert report.status_code == 201, report.text
    return case, sample, captures, report.json(), prefix + f"/reports/{report.json()['id']}"


def test_api_all_sections_exports_comparison_and_historical_read_only_snapshot(intake):
    client, app, _ = intake
    _, _, captures, report, uri = setup(intake)
    original = client.get(uri + "/download").content
    with app.state.sessions() as session:
        before = session.scalar(select(func.count()).select_from(AuditEvent))
        for capture_id in captures:
            capture = session.get(RuntimeCapture, capture_id)
            (app.state.settings.evidence_root / capture.artifact_key).unlink()
    for section in ["process", "filesystem", "network", "sensitive_access", "activity"]:
        response = client.get(uri + "/runtime-review", params={"section": section, "limit": 1})
        assert response.status_code == 200, response.text
        assert response.json()["source_report_sha256"] == hashlib.sha256(original).hexdigest()
        assert response.headers["x-export-sha256"] == hashlib.sha256(response.content).hexdigest()
        assert response.headers["cache-control"] == "no-store"
        html = client.get(
            uri + "/runtime-review/export/html", params={"section": section, "limit": 1}
        )
        assert html.status_code == 200 and "Selected page" in html.text
        assert "default-src 'none'" in html.headers["content-security-policy"]
    params = {"left_capture_id": captures[0], "right_capture_id": captures[1]}
    for path in ["/runtime-comparison", "/runtime-comparison/export/html"]:
        response = client.get(uri + path, params=params)
        assert response.status_code == 200, response.text
    result = client.get(uri + "/runtime-comparison", params=params).json()
    assert result["comparison_summary"]["both_selected_captures"] == 2
    assert client.get(uri + "/download").content == original
    with app.state.sessions() as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == before
        assert session.scalar(select(func.count()).select_from(ForensicReport)) == 1


@pytest.mark.parametrize(
    "mode",
    [
        "tamper",
        "input",
        "schema",
        "run",
        "duplicate",
        "trace",
        "hash",
        "representation",
        "identity",
        "duplicate_json",
    ],
)
def test_snapshot_integrity_and_rehashed_invalid_sources_rejected(intake, mode):
    client, app, _ = intake
    _, _, _, report, uri = setup(intake)
    with app.state.sessions.begin() as session:
        saved = session.get(ForensicReport, report["id"])
        path = app.state.settings.evidence_root / saved.artifact_key
        data = json.loads(path.read_bytes())
        if mode == "tamper":
            path.write_bytes(b"tampered")
        else:
            source = data["runtime_captures"][0]
            if mode == "input":
                saved.input_sha256 = "b" * 64
            elif mode == "schema":
                saved.schema_version = 1
            elif mode == "run":
                source["source_run_id"] = "wrong"
            elif mode == "duplicate":
                data["runtime_captures"].append(copy.deepcopy(source))
            elif mode == "trace":
                source["data"]["events"][0]["pid"] = -1
            elif mode == "hash":
                source["artifact_sha256"] = "no"
            elif mode == "representation":
                source["representation"] = "verified_execution"
            elif mode == "identity":
                source["data"]["input_sha256"] = "b" * 64
            raw = json.dumps(data).encode()
            if mode == "duplicate_json":
                raw = b'{"schema_version":2,' + raw[1:]
            path.write_bytes(raw)
            saved.artifact_sha256 = hashlib.sha256(raw).hexdigest()
            saved.size_bytes = len(raw)
    assert client.get(uri + "/runtime-review").status_code == 409


@pytest.mark.parametrize(
    "setting,endpoint",
    [
        ("max_runtime_review_bytes", "/runtime-review"),
        ("max_runtime_review_html_bytes", "/runtime-review/export/html"),
        ("max_runtime_review_groups", "/runtime-review"),
        ("max_runtime_review_events", "/runtime-review"),
    ],
)
def test_api_operational_bounds(intake, setting, endpoint):
    client, app, _ = intake
    _, _, _, _, uri = setup(intake)
    setattr(app.state.settings, setting, 1024 if "bytes" in setting else 1)
    assert client.get(uri + endpoint).status_code == 413


def test_permissions_case_scope_selection_query_contracts_and_openapi(intake):
    client, app, _ = intake
    case, sample, captures, _, uri = setup(intake)
    comparison = {"left_capture_id": captures[0], "right_capture_id": captures[1]}
    user = create_user(app.state.sessions, "runtimeviewer", "runtime-viewer-password")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "runtime-viewer-password"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    for path, params in [
        ("/runtime-review", {}),
        ("/runtime-review/export/html", {}),
        ("/runtime-comparison", comparison),
        ("/runtime-comparison/export/html", comparison),
    ]:
        assert client.get(uri + path, params=params, headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.get(uri + "/runtime-review", headers=headers).status_code == 200
    assert (
        client.get(uri + "/runtime-review", params={"capture_id": str(uuid4())}).status_code == 404
    )
    for params in [
        {"limit": 201},
        {"offset": -1},
        {"bucket_seconds": 0},
        {"section": "invalid"},
        {"capture_id": "invalid"},
    ]:
        assert client.get(uri + "/runtime-review", params=params).status_code == 422
    assert (
        client.get(
            uri + "/runtime-comparison", params={**comparison, "right_capture_id": captures[0]}
        ).status_code
        == 422
    )
    assert (
        client.get(
            uri + "/runtime-comparison", params={**comparison, "section": "activity"}
        ).status_code
        == 422
    )
    assert (
        client.get(
            uri + "/runtime-comparison", params={**comparison, "right_capture_id": str(uuid4())}
        ).status_code
        == 404
    )
    assert client.get(uri + "/runtime-comparison").status_code == 422
    assert (
        client.get(uri.replace(sample["id"], str(uuid4())) + "/runtime-review").status_code == 404
    )
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(uri.replace(case, other) + "/runtime-review").status_code == 404
    schema = client.get("/openapi.json").json()
    assert any(path.endswith("/runtime-review") for path in schema["paths"])
    client.headers.pop("Authorization")
    assert client.get(uri + "/runtime-review").status_code == 401


def test_html_escapes_all_collector_strings_and_preserves_pagination():
    data = full_trace()
    data["events"][0]["name"] = '</pre><script>alert("x")</script>'
    data["events"][4]["name"] = data["events"][0]["name"]
    doc = document(data)
    result = view(doc, limit=1)
    raw = json.dumps(result).encode()
    html = render(raw, 1000000)
    assert b"<script>" not in html and b"&lt;script&gt;" in html
    assert b"Selected page" in html and b"&quot;limit&quot;: 1" in html
    with pytest.raises(HTTPException) as error:
        render(raw, 1024)
    assert error.value.status_code == 413


def test_filter_preserves_original_source_index_and_offsets_are_normalized_for_extrema():
    doc = document(full_trace(), full_trace())
    selected = doc["runtime_captures"][1]
    selected["data"]["events"][0]["timestamp"] = "2026-10-21T12:00:01+02:00"
    result = view(doc, capture_id=selected["capture_id"])
    assert result["sources"][0]["snapshot_pointer"] == "/runtime_captures/1"
    start = next(item for item in result["items"] if item["identity"]["action"] == "start")
    assert start["first_observed_at"] == "2026-10-21T10:00:01+00:00"
    assert start["evidence"][0]["snapshot_pointer"].startswith("/runtime_captures/1/")


@pytest.mark.parametrize("field,value", [("schema_version", True), ("input_sha256", "b" * 64)])
def test_trace_identity_rejects_boolean_schema_and_different_sample(field, value):
    doc = document()
    doc["runtime_captures"][0]["data"][field] = value
    with pytest.raises(ValueError):
        validate(doc)
