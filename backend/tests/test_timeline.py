"""Timeline permissions, chronology, source references, bounds and no mutation."""

import copy
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from test_jobs import fixture_sample
from test_runtime_captures import trace

from godeep.persistence.models import AuditEvent, RuntimeCapture
from godeep.services.auth import create_user


def setup(intake):
    client, _, _ = intake
    case, sample = fixture_sample(client)
    payload = trace(sample["sha256"])
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}"
    first = client.post(prefix + "/runtime-captures", json=payload).json()
    second_payload = copy.deepcopy(payload)
    second_payload["source_run_id"] = "second-run"
    second_payload["events"][-1]["timestamp"] = "2026-10-21T12:00:03+02:00"
    second = client.post(prefix + "/runtime-captures", json=second_payload).json()
    return case, sample, [first, second], prefix + "/runtime-timeline"


def test_ordering_pagination_provenance_duplicates_and_no_mutation(intake):
    client, app, _ = intake
    _, _, sources, uri = setup(intake)
    with app.state.sessions() as session:
        before = session.scalar(select(func.count()).select_from(AuditEvent))
    selection = {"capture_ids": [source["id"] for source in reversed(sources)]}
    response = client.post(uri, json=selection)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 6  # Same event IDs across different runs are separate observations.
    keys = [
        (
            datetime.fromisoformat(item["event"]["timestamp"]),
            item["capture_id"],
            item["event"]["event_id"],
        )
        for item in body["items"]
    ]
    assert keys == sorted(keys)
    assert body["items"][-1]["event"]["timestamp"] == "2026-10-21T12:00:03+02:00"
    for item in body["items"]:
        source = next(source for source in sources if source["id"] == item["capture_id"])
        assert item["evidence"]["artifact_sha256"] == source["artifact_sha256"]
        assert item["evidence"]["event_id"] == item["event"]["event_id"]
    assert body["sources"][0]["attribution"] == "collector_asserted_not_verified"
    assert body["sources"][0]["coverage"]["sensitive_access"] == "not_collected"
    page = client.post(uri, json={**selection, "offset": 1, "limit": 2}).json()
    assert page["items"] == body["items"][1:3] and page["total"] == 6
    assert response.headers["cache-control"] == "no-store"
    with app.state.sessions() as session:
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == before


def test_kind_and_inclusive_time_filters_and_empty_view(intake):
    client, _, _ = intake
    _, _, sources, uri = setup(intake)
    selection = {"capture_ids": [source["id"] for source in sources], "kinds": ["network"]}
    assert client.post(uri, json=selection).json()["total"] == 2
    filtered = client.post(
        uri,
        json={
            **selection,
            "started_at": "2026-10-21T10:00:03Z",
            "ended_at": "2026-10-21T10:00:03Z",
        },
    ).json()
    assert filtered["total"] == 1
    assert client.post(uri, json={**selection, "kinds": ["sensitive_access"]}).json()["total"] == 0
    assert client.post(uri, json={**selection, "offset": 100}).json()["items"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {"capture_ids": []},
        {"capture_ids": [str(uuid4())] * 2},
        {"capture_ids": [str(uuid4()) for _ in range(11)]},
        {"capture_ids": [str(uuid4())], "started_at": "2026-10-21T00:00:00"},
        {
            "capture_ids": [str(uuid4())],
            "started_at": "2026-10-22T00:00:00Z",
            "ended_at": "2026-10-21T00:00:00Z",
        },
        {"capture_ids": [str(uuid4())], "limit": 201},
    ],
)
def test_invalid_selection_and_filters(intake, payload):
    client, _, _ = intake
    _, _, _, uri = setup(intake)
    assert client.post(uri, json=payload).status_code == 422


def test_viewer_read_outsider_and_cross_case_denied(intake):
    client, app, _ = intake
    case, sample, sources, uri = setup(intake)
    payload = {"capture_ids": [sources[0]["id"]]}
    user = create_user(app.state.sessions, "timelineviewer", "timeline-viewer-password")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "timeline-viewer-password"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert client.post(uri, json=payload, headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.post(uri, json=payload, headers=headers).status_code == 200
    other_case, other_sample = fixture_sample(client)
    other_uri = f"/api/v1/cases/{other_case}/samples/{other_sample['id']}/runtime-timeline"
    assert client.post(other_uri, json=payload).status_code == 404
    assert client.post(uri, json={"capture_ids": [str(uuid4())]}).status_code == 404
    client.headers.pop("Authorization")
    assert client.post(uri, json=payload).status_code == 401


@pytest.mark.parametrize("change", ["tampered", "metadata", "source_bound", "output_bound"])
def test_source_integrity_and_bounds(intake, change):
    client, app, _ = intake
    _, _, sources, uri = setup(intake)
    if change in {"tampered", "metadata"}:
        with app.state.sessions.begin() as session:
            stored = session.get(RuntimeCapture, sources[0]["id"])
            if change == "tampered":
                (app.state.settings.evidence_root / stored.artifact_key).write_bytes(b"changed")
            else:
                stored.source_run_id = "incorrect-reference"
        expected = 409
    else:
        if change == "source_bound":
            app.state.settings.max_timeline_source_bytes = 1
        else:
            app.state.settings.max_timeline_bytes = 1
        expected = 413
    assert client.post(uri, json={"capture_ids": [sources[0]["id"]]}).status_code == expected
