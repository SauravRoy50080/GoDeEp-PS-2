"""Exact offline advisory claims preserve declaration provenance and limitations."""

import copy
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from test_resource_inventory import apk_members

from godeep.analysis.correlation.libraries import review_libraries
from godeep.core.config import Settings
from godeep.integrations.intelligence.library_feed import load_library_feed
from godeep.workers.runner import run_once

NOW = datetime(2026, 10, 21, tzinfo=UTC)


def feed(now=NOW):
    return {
        "schema_version": 1,
        "feed_id": "synthetic-library-feed",
        "source_name": "Synthetic fixtures only",
        "published_at": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
        "advisories": [
            {
                "id": "TEST-1",
                "group_id": "org.example",
                "artifact_id": "demo",
                "versions": ["1.2.3"],
                "assertion": "affected",
                "title": "Synthetic declaration review",
                "reference": "https://example.org/advisory",
            }
        ],
    }


def configure(tmp_path, document=None, **overrides):
    path = tmp_path / "libraries.json"
    raw = json.dumps(document or feed()).encode()
    path.write_bytes(raw)
    return Settings(
        _env_file=None,
        library_feed_path=path,
        library_feed_sha256=hashlib.sha256(raw).hexdigest(),
        **overrides,
    )


def inventory():
    return {
        "coverage": "selected_members_inspected",
        "library_candidates": [
            {
                "member": "META-INF/maven/org.example/demo/pom.properties",
                "sha256": "a" * 64,
                "kind": "maven_properties",
                "groupId": "org.example",
                "artifactId": "demo",
                "version": "1.2.3",
                "path_identity_matches": True,
                "identity_verified": False,
            }
        ],
    }


def test_exact_match_retains_hash_and_declaration_evidence(tmp_path):
    settings = configure(tmp_path)
    result = review_libraries(inventory(), settings, NOW)
    lib = result["libraries"][0]
    assert lib["lookup_status"] == "matched_source_claims"
    assert lib["matches"][0]["id"] == "TEST-1"
    assert lib["matches"][0]["assertion"] == "affected"
    assert lib["evidence"][0]["sha256"] == "a" * 64
    assert not lib["identity_verified"] and lib["requires_review"]
    assert result["feed"]["feed_sha256"] == settings.library_feed_sha256
    assert "index" not in result["feed"] and result["feed"]["network_requests"] == 0
    assert "risk_score" not in result


@pytest.mark.parametrize(
    "key,value",
    [
        ("groupId", "ORG.EXAMPLE"),
        ("artifactId", "other"),
        ("version", "1.2.30"),
        ("version", "1.2.3-release"),
    ],
)
def test_versions_and_coordinates_are_not_guessed(tmp_path, key, value):
    data = inventory()
    data["library_candidates"][0][key] = value
    result = review_libraries(data, configure(tmp_path), NOW)
    assert result["libraries"][0]["lookup_status"] == "no_exact_match_in_local_feed"


def test_conflicts_withdrawals_expiry_and_truncation_remain_visible(tmp_path):
    data = feed()
    base = data["advisories"][0]
    data["advisories"] += [
        {**base, "id": "TEST-2", "assertion": "not_affected"},
        {**base, "id": "TEST-3", "withdrawn": True},
        {**base, "id": "TEST-4", "valid_until": (NOW - timedelta(seconds=1)).isoformat()},
    ]
    result = review_libraries(inventory(), configure(tmp_path, data, max_library_matches=1), NOW)
    lib = result["libraries"][0]
    assert lib["source_claims_conflict"] and lib["matches_truncated"]
    assert lib["active_match_count"] == 2 and len(lib["matches"]) == 1
    assert lib["withdrawn_match_count"] == lib["expired_match_count"] == 1
    assert result["coverage"] == "partial"


def test_group_duplicates_and_unresolved_metadata(tmp_path):
    data = inventory()
    first = data["library_candidates"][0]
    data["library_candidates"] += [
        copy.deepcopy(first),
        {**first, "member": "other/pom.properties"},
        {**first, "member": "conflict/pom.properties", "path_identity_matches": False},
        {"kind": "version_marker", "member": "META-INF/demo.version", "sha256": "b" * 64},
    ]
    result = review_libraries(data, configure(tmp_path, max_review_evidence=1), NOW)
    assert len(result["libraries"]) == 1 and result["libraries"][0]["evidence_count"] == 2
    assert result["libraries"][0]["evidence_truncated"]
    assert len(result["unresolved"]) == 2 and result["coverage"] == "partial"


@pytest.mark.parametrize(
    "change,expected",
    [
        ("hash", "feed_hash_mismatch"),
        ("expired", "feed_expired"),
        ("future", "feed_from_future"),
        ("stale", "feed_stale"),
        ("duplicate_id", "feed_invalid"),
        ("duplicate_version", "feed_invalid"),
        ("naive", "feed_invalid"),
        ("range", "feed_invalid"),
        ("missing", "feed_unavailable"),
        ("size", "feed_size_limit"),
    ],
)
def test_feed_provenance_freshness_and_schema_failures(tmp_path, change, expected):
    data = feed()
    if change == "expired":
        data["published_at"] = (NOW - timedelta(days=2)).isoformat()
        data["valid_until"] = (NOW - timedelta(days=1)).isoformat()
    elif change == "future":
        data["published_at"] = (NOW + timedelta(hours=1)).isoformat()
    elif change == "stale":
        data["published_at"] = (NOW - timedelta(days=31)).isoformat()
    elif change == "duplicate_id":
        data["advisories"].append(copy.deepcopy(data["advisories"][0]))
    elif change == "duplicate_version":
        data["advisories"][0]["versions"] *= 2
    elif change == "naive":
        data["published_at"] = "2026-10-20T00:00:00"
    elif change == "range":
        data["advisories"][0]["versions"] = [">=1.0"]
    settings = configure(tmp_path, data)
    if change == "hash":
        settings.library_feed_sha256 = "0" * 64
    elif change == "missing":
        settings.library_feed_path.unlink()
    elif change == "size":
        settings.max_library_feed_bytes = 1
    assert load_library_feed(settings, NOW)["status"] == expected
    assert (
        review_libraries(inventory(), settings, NOW)["libraries"][0]["lookup_status"]
        == "not_checked"
    )


def test_no_feed_or_incomplete_configuration_never_implies_safe(tmp_path):
    result = review_libraries(inventory(), Settings(_env_file=None), NOW)
    assert result["feed"]["status"] == "not_configured" and result["coverage"] == "not_checked"
    settings = configure(tmp_path)
    settings.library_feed_sha256 = None
    assert load_library_feed(settings, NOW)["status"] == "invalid_configuration"
    settings.library_feed_path = type(tmp_path)("relative.json")
    assert load_library_feed(settings, NOW)["status"] == "invalid_configuration"


def test_feed_cli_and_worker_report_integration(intake, tmp_path):
    client, app, _ = intake
    settings = configure(tmp_path, feed(datetime.now(UTC)))
    validation = subprocess.run(
        [
            sys.executable,
            "-m",
            "godeep.integrations.intelligence.library_feed",
            str(settings.library_feed_path),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert validation.returncode == 0, validation.stderr
    app.state.settings.library_feed_path = settings.library_feed_path
    app.state.settings.library_feed_sha256 = settings.library_feed_sha256
    raw = apk_members(
        {
            "META-INF/maven/org.example/demo/pom.properties": (
                b"groupId=org.example\nartifactId=demo\nversion=1.2.3\n"
            )
        }
    )
    case = client.post("/api/v1/cases", json={"name": "Library review"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=raw,
        headers={"Content-Type": "application/octet-stream", "X-Filename": "libraries.apk"},
    ).json()
    response = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample["id"], "adapter": "library_review"},
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert "library_feed_path" not in job["config"] and "library_feed_sha256" not in job["config"]
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    result = client.get(base + "/result").json()["data"]
    assert result["library_review"]["libraries"][0]["matches"][0]["id"] == "TEST-1"
    assert result["library_review"]["feed"]["feed_sha256"] == settings.library_feed_sha256
    assert (
        result["observations"]["library_candidates"][0]["vulnerability_status"]
        == "see_library_review"
    )
    report = client.post(
        f"/api/v1/cases/{case}/samples/{sample['id']}/reports", json={"job_ids": [job["id"]]}
    )
    assert report.status_code == 201, report.text
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404


@pytest.mark.parametrize("change", ["duplicate_key", "nonfinite", "boolean_schema"])
def test_ambiguous_json_and_schema_types_rejected(tmp_path, change):
    settings = configure(tmp_path)
    raw = settings.library_feed_path.read_bytes()
    if change == "duplicate_key":
        raw = raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
    elif change == "nonfinite":
        raw = raw.replace(b'"schema_version": 1', b'"schema_version": NaN')
    else:
        raw = raw.replace(b'"schema_version": 1', b'"schema_version": true')
    settings.library_feed_path.write_bytes(raw)
    settings.library_feed_sha256 = hashlib.sha256(raw).hexdigest()
    assert load_library_feed(settings, NOW)["status"] == "feed_invalid"


def test_withdrawn_only_claims_do_not_become_active_matches(tmp_path):
    data = feed()
    data["advisories"][0]["withdrawn"] = True
    result = review_libraries(inventory(), configure(tmp_path, data), NOW)
    group = result["libraries"][0]
    assert not group["matches"] and group["active_match_count"] == 0
    assert group["lookup_status"] == "excluded_claims_only"
    assert group["withdrawn_match_count"] == 1
