"""Evidence-bound analyst judgments, append-only revisions, exports and migration."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from alembic import command
from sqlalchemy import event, func, inspect, select
from test_network_correlation import setup as report_setup

from godeep.persistence.models import AuditEvent, ForensicReport, ReportReviewEntry
from godeep.services.auth import create_user
from godeep.services.report_reviews import resolve, tokens


def setup(intake):
    client, _, _ = intake
    case, sample, job, report, uri = report_setup(intake)
    document = client.get(uri + "/download").json()
    payload = {
        "expected_report_sha256": report["artifact_sha256"],
        "text": "Review the recorded evidence",
        "decision": "follow_up",
        "evidence_references": [
            {
                "source_kind": "analysis",
                "source_id": job["id"],
                "pointer": "/analyses/0/data/coverage",
            }
        ],
    }
    return case, sample, report, uri, document, payload


def test_review_source_binding_audit_history_revision_and_unchanged_report(intake):
    client, app, _ = intake
    _, _, report, uri, document, payload = setup(intake)
    original = client.get(uri + "/download").content
    response = client.post(uri + "/reviews", json=payload)
    assert response.status_code == 201, response.text
    entry = response.json()
    assert entry["thread_id"] == entry["id"] and entry["supersedes_id"] is None
    ref = entry["evidence_references"][0]
    assert ref["source_sha256"] == document["analyses"][0]["result_sha256"]
    value = json.dumps(
        document["analyses"][0]["data"]["coverage"],
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    assert ref["snapshot_value_sha256"] == hashlib.sha256(value).hexdigest()
    revised = client.post(
        uri + "/reviews",
        json={
            **payload,
            "supersedes_id": entry["id"],
            "decision": "supported",
            "text": "Reviewed with context",
        },
    )
    assert revised.status_code == 201, revised.text
    assert revised.json()["thread_id"] == entry["id"]
    history = client.get(uri + "/reviews").json()
    assert history["total"] == 2
    assert history["items"][0]["text"] == payload["text"]
    current = client.get(uri + "/reviews?current=true").json()
    assert current["total"] == 1 and current["items"][0]["id"] == revised.json()["id"]
    assert (
        client.post(uri + "/reviews", json={**payload, "supersedes_id": entry["id"]}).status_code
        == 409
    )
    assert client.get(uri + "/download").content == original
    assert client.patch(uri + "/reviews", json=payload).status_code == 405
    assert client.delete(uri + "/reviews").status_code == 405
    with app.state.sessions() as session:
        assert session.get(ForensicReport, report["id"]).review_entry_count == 2
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "report.review_appended")
        ).all()
        assert len(events) == 2 and events[-1].details["reference_count"] == 1


def test_runtime_event_reference_and_conflicting_independent_threads(intake):
    client, _, _ = intake
    _, _, _, uri, document, payload = setup(intake)
    source = document["runtime_captures"][0]
    payload["evidence_references"] = [
        {
            "source_kind": "runtime_capture",
            "source_id": source["capture_id"],
            "pointer": "/runtime_captures/0/data/events/0",
        }
    ]
    for decision in ["supported", "disputed"]:
        result = client.post(uri + "/reviews", json={**payload, "decision": decision})
        assert result.status_code == 201, result.text
        assert result.json()["evidence_references"][0]["source_sha256"] == source["artifact_sha256"]
    assert client.get(uri + "/reviews?current=true").json()["total"] == 2


@pytest.mark.parametrize(
    "pointer",
    [
        "/sample/sha256",
        "/analyses/0/result_sha256",
        "/analyses/00/data",
        "/analyses/-/data",
        "/analyses/0/data/no_such_field",
        "/analyses/0/data/~2",
        "#/analyses/0/data",
        "/analyses/999/data",
        "/runtime_captures/0/data/events/0",
    ],
)
def test_invalid_or_wrong_source_pointers_rejected(intake, pointer):
    client, _, _ = intake
    _, _, _, uri, _, payload = setup(intake)
    payload["evidence_references"][0]["pointer"] = pointer
    assert client.post(uri + "/reviews", json=payload).status_code == 422
    assert client.get(uri + "/reviews").json()["total"] == 0


def test_json_pointer_escaping_no_unicode_normalization_or_array_coercion():
    data = {"a/b": {"~1": ["value"]}, "00": "key"}
    assert resolve(data, tokens("/a~1b/~01/0")) == "value"
    assert resolve(data, tokens("/00")) == "key"
    for pointer in ["/a~1b/~01/00", "/a~1b/~01/-", "/a~1b/~01/-1", "/a~1b/~01/9"]:
        with pytest.raises((ValueError, IndexError)):
            resolve(data, tokens(pointer))
    with pytest.raises(ValueError):
        tokens("/" + "/".join(["x"] * 33))


@pytest.mark.parametrize(
    "mode", ["blank", "large", "no_reference", "duplicate", "wrong_id", "wrong_hash", "extra"]
)
def test_request_contracts(intake, mode):
    client, _, _ = intake
    _, _, _, uri, _, payload = setup(intake)
    if mode == "blank":
        payload["text"] = " \n"
    elif mode == "large":
        payload["text"] = "x" * 4001
    elif mode == "no_reference":
        payload["evidence_references"] = []
    elif mode == "duplicate":
        payload["evidence_references"] *= 2
    elif mode == "wrong_id":
        payload["evidence_references"][0]["source_id"] = str(uuid4())
    elif mode == "wrong_hash":
        payload["expected_report_sha256"] = "b" * 64
    else:
        payload["score"] = 99
    assert client.post(uri + "/reviews", json=payload).status_code == (
        409 if mode == "wrong_hash" else 422
    )


def user_headers(client, app, name):
    user = create_user(app.state.sessions, name, "review-password-long")
    token = client.post(
        "/api/v1/auth/login", json={"username": name, "password": "review-password-long"}
    ).json()["access_token"]
    return user, {"Authorization": "Bearer " + token}


def test_permissions_authors_owner_corrections_and_case_scope(intake):
    client, app, _ = intake
    case, sample, _, uri, _, payload = setup(intake)
    user, headers = user_headers(client, app, "reviewer")
    assert client.get(uri + "/reviews", headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"})
    assert client.get(uri + "/reviews", headers=headers).status_code == 200
    assert client.post(uri + "/reviews", headers=headers, json=payload).status_code == 403
    client.put(f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "analyst"})
    authored = client.post(uri + "/reviews", headers=headers, json=payload)
    assert authored.status_code == 201
    own = client.post(uri + "/reviews", json=payload).json()
    assert (
        client.post(
            uri + "/reviews", headers=headers, json={**payload, "supersedes_id": own["id"]}
        ).status_code
        == 403
    )
    correction = client.post(
        uri + "/reviews", json={**payload, "supersedes_id": authored.json()["id"]}
    )
    assert correction.status_code == 201  # Owner may correct a member thread.
    assert (
        client.post(
            uri + "/reviews",
            headers=headers,
            json={**payload, "supersedes_id": correction.json()["id"]},
        ).status_code
        == 201
    )
    other = client.post("/api/v1/cases", json={"name": "other"}).json()["id"]
    assert client.get(uri.replace(case, other) + "/reviews").status_code == 404
    assert client.get(uri.replace(sample["id"], str(uuid4())) + "/reviews").status_code == 404
    client.headers.pop("Authorization")
    assert client.get(uri + "/reviews").status_code == 401


def test_pagination_thread_filter_and_complete_passive_exports(intake):
    client, _, _ = intake
    _, _, report, uri, _, payload = setup(intake)
    first = client.post(
        uri + "/reviews", json={**payload, "text": "</pre><script>alert(1)</script>"}
    ).json()
    second = client.post(uri + "/reviews", json={**payload, "supersedes_id": first["id"]}).json()
    client.post(
        uri + "/reviews",
        json={"expected_report_sha256": report["artifact_sha256"], "text": "Separate comment"},
    )
    assert client.get(uri + "/reviews?limit=1&offset=1").json()["items"][0]["id"] == second["id"]
    assert client.get(uri + f"/reviews?thread_id={first['id']}").json()["total"] == 2
    assert client.get(uri + f"/reviews?thread_id={uuid4()}").status_code == 404
    assert client.get(uri + "/reviews?limit=101").status_code == 422
    raw = client.get(uri + "/reviews/export/json")
    assert raw.status_code == 200 and raw.json()["total"] == 3
    assert len(raw.json()["current_entry_ids"]) == 2
    assert raw.headers["x-export-sha256"] == hashlib.sha256(raw.content).hexdigest()
    html = client.get(uri + "/reviews/export/html")
    assert html.status_code == 200
    assert "<script>" not in html.text and "&lt;script&gt;" in html.text
    assert "Superseded entry" in html.text and "Current entry" in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"]
    assert html.headers["x-source-report-sha256"] == report["artifact_sha256"]


@pytest.mark.parametrize(
    "mode", ["report_bytes", "report_rehash", "entry_hash", "reference_hash", "lineage"]
)
def test_tampered_snapshot_or_stored_history_is_rejected(intake, mode):
    client, app, _ = intake
    _, _, report, uri, _, payload = setup(intake)
    entry = client.post(uri + "/reviews", json=payload).json()
    with app.state.sessions.begin() as session:
        saved = session.get(ForensicReport, report["id"])
        path = app.state.settings.evidence_root / saved.artifact_key
        row = session.get(ReportReviewEntry, entry["id"])
        if mode == "report_bytes":
            path.write_bytes(b"changed")
        elif mode == "report_rehash":
            raw = path.read_bytes() + b"\n"
            path.write_bytes(raw)
            saved.artifact_sha256 = hashlib.sha256(raw).hexdigest()
            saved.size_bytes = len(raw)
        elif mode == "entry_hash":
            row.report_sha256 = "b" * 64
        elif mode == "reference_hash":
            row.evidence_references = [
                {**row.evidence_references[0], "snapshot_value_sha256": "b" * 64}
            ]
        else:
            row.evidence_references = [{"source_kind": "analysis"}]
    assert client.get(uri + "/reviews").status_code == 409


@pytest.mark.parametrize("mode", ["entries", "json", "html", "reference_bytes"])
def test_operational_bounds_and_quota_rollback(intake, mode):
    client, app, _ = intake
    _, _, report, uri, _, payload = setup(intake)
    settings = app.state.settings
    if mode == "reference_bytes":
        settings.max_report_review_reference_bytes = 1
        assert client.post(uri + "/reviews", json=payload).status_code == 413
    else:
        assert client.post(uri + "/reviews", json=payload).status_code == 201
        if mode == "entries":
            settings.max_report_review_entries = 1
            assert client.post(uri + "/reviews", json=payload).status_code == 413
        elif mode == "json":
            settings.max_report_review_bytes = 1024
            assert client.get(uri + "/reviews/export/json").status_code == 413
        else:
            settings.max_report_review_html_bytes = 1024
            assert client.get(uri + "/reviews/export/html").status_code == 413
    with app.state.sessions() as session:
        assert session.get(ForensicReport, report["id"]).review_entry_count == (
            0 if mode == "reference_bytes" else 1
        )


def test_transaction_rolls_back_entry_quota_and_audit_together(intake):
    client, app, _ = intake
    _, _, report, uri, _, payload = setup(intake)
    engine = app.state.sessions.kw["bind"]

    def fail(connection, cursor, statement, parameters, context, many):
        if "INSERT INTO audit_events" in statement:
            raise RuntimeError("injected audit failure")

    event.listen(engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(RuntimeError, match="injected audit failure"):
            client.post(uri + "/reviews", json=payload)
    finally:
        event.remove(engine, "before_cursor_execute", fail)
    with app.state.sessions() as session:
        assert session.get(ForensicReport, report["id"]).review_entry_count == 0
        assert session.scalar(select(func.count()).select_from(ReportReviewEntry)) == 0


def test_concurrent_revision_cannot_fork_and_quota_is_not_leaked(intake):
    client, app, _ = intake
    _, _, report, uri, _, payload = setup(intake)
    first = client.post(uri + "/reviews", json=payload).json()

    def revise(number):
        return client.post(
            uri + "/reviews",
            json={**payload, "supersedes_id": first["id"], "text": f"Revision {number}"},
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = sorted(pool.map(revise, [1, 2]))
    assert codes[0] == 201 and codes[1] in (409, 503), codes
    with app.state.sessions() as session:
        assert session.get(ForensicReport, report["id"]).review_entry_count == 2
        assert session.scalar(select(func.count()).select_from(ReportReviewEntry)) == 2


def test_migration_roundtrip_preserves_original_report(intake):
    client, app, config = intake
    _, _, report, uri, _, payload = setup(intake)
    first = client.post(uri + "/reviews", json=payload)
    assert first.status_code == 201
    assert (
        client.post(
            uri + "/reviews", json={**payload, "supersedes_id": first.json()["id"]}
        ).status_code
        == 201
    )
    engine = app.state.sessions.kw["bind"]
    command.downgrade(config, "0005_runtime_captures")
    assert "report_review_entries" not in inspect(engine).get_table_names()
    command.upgrade(config, "head")
    assert client.get(uri + "/download").status_code == 200
    assert client.get(uri + "/reviews").json()["total"] == 0
    with app.state.sessions() as session:
        assert session.get(ForensicReport, report["id"]).review_entry_count == 0


@pytest.mark.parametrize("value", ["bad\0text", "bad\ud800text"])
def test_storage_unsafe_unicode_is_rejected_at_validation(value):
    from godeep.schemas.report_reviews import ReviewCreate

    with pytest.raises(ValueError):
        ReviewCreate(expected_report_sha256="a" * 64, text=value)


def test_thread_lineage_mismatch_and_cross_report_parent_are_rejected(intake):
    client, app, _ = intake
    _, _, _, uri, _, payload = setup(intake)
    first = client.post(uri + "/reviews", json=payload).json()
    other = client.post(uri + "/reviews", json=payload).json()
    child = client.post(uri + "/reviews", json={**payload, "supersedes_id": first["id"]}).json()
    with app.state.sessions.begin() as session:
        session.get(ReportReviewEntry, child["id"]).thread_id = other["id"]
    assert client.get(uri + "/reviews").status_code == 409
    _, _, _, second_uri, _, second_payload = setup(intake)
    assert (
        client.post(
            second_uri + "/reviews", json={**second_payload, "supersedes_id": first["id"]}
        ).status_code
        == 404
    )
