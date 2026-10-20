"""Semantic observation differences, coverage cautions and case-scoped comparisons."""

import hashlib
import io
import json
from zipfile import ZipFile

import pytest
from android_fixtures import MANIFEST, binary_manifest
from test_dex_calls import code_fixture

from godeep.analysis.correlation.comparison import compare
from godeep.analysis.static.manifest import parse_manifest
from godeep.core.config import Settings
from godeep.persistence.models import AnalysisJob
from godeep.services.auth import create_user
from godeep.workers.runner import run_once

SETTINGS = Settings(_env_file=None)


def observation(xml=MANIFEST):
    return {
        "manifest": parse_manifest(binary_manifest(xml), SETTINGS),
        "signing": {"certificates": []},
        "review": {"findings": [], "network_candidates": []},
        "coverage": {
            "manifest": {"status": "parsed"},
            "signing": "metadata_extraction_only",
            "dex": "call_sites_decoded",
            "correlation": "available_observations_grouped",
        },
        "tool_versions": {"decoder": "1"},
        "component_versions": {"rules": "1"},
    }


def test_permissions_and_component_changes_have_evidence():
    left = observation()
    right = observation(
        MANIFEST.replace('android:maxSdkVersion="32"', 'android:maxSdkVersion="33"').replace(
            'android:exported="false"', 'android:exported="true"'
        )
    )
    result = compare(left, right, SETTINGS)
    permission = result["categories"]["permissions"]
    assert permission["counts"]["changed"] == 1
    assert permission["changed"][0]["left"]["evidence"][0]["sha256"]
    assert result["categories"]["components"]["counts"]["changed"] == 1
    assert result["categories"]["feed_assertions"]["absence_interpretation"] == "not_established"


def test_selector_and_hash_differences_do_not_fake_semantic_changes():
    left, right = observation(), observation()
    right["manifest"]["source"]["sha256"] = "f" * 64
    right["manifest"]["permissions"].reverse()
    for entry in right["manifest"]["permissions"]:
        entry["evidence_selector"] += "changed-index"
    result = compare(left, right, SETTINGS)
    assert all(
        category["counts"] == {"left_only": 0, "right_only": 0, "changed": 0}
        for category in result["categories"].values()
    )


def test_partial_coverage_and_profile_changes_cannot_establish_absence():
    left, right = observation(), observation()
    right["manifest"]["permissions"] = []
    right["coverage"]["manifest"]["status"] = "failed"
    result = compare(left, right, SETTINGS, configurations_equal=False)
    assert result["categories"]["permissions"]["counts"]["left_only"] == 2
    assert result["categories"]["permissions"]["absence_interpretation"] == "not_established"
    assert "analysis_configurations_differ" in result["warnings"]
    right["tool_versions"] = {"decoder": "2"}
    right["manifest"]["sdk"]["target_effective"] = 34
    result = compare(left, right, SETTINGS)
    assert "tool_versions_differ" in result["warnings"]
    assert "manifest_sdk_contexts_differ" in result["warnings"]


def test_candidate_deduplication_certificate_identity_and_output_caps():
    left, right = observation(), observation()
    right["review"]["network_candidates"] = [
        {
            "kind": "domain",
            "value": "EXAMPLE.ORG.",
            "evidence": [{"member": "classes.dex", "sha256": "a" * 64}],
        },
        {
            "kind": "domain",
            "value": "example.org",
            "evidence": [{"member": "classes2.dex", "sha256": "b" * 64}],
        },
        {"kind": "domain", "value": "example.net", "evidence": []},
    ]
    right["signing"]["certificates"] = [{"sha256": "c" * 64, "sources": [{"block": "v2"}]}]
    result = compare(left, right, Settings(_env_file=None, max_comparison_items=1))
    network = result["categories"]["network_candidates"]
    # An empty evidence list produces no backed observation.
    assert network["counts"]["right_only"] == 1
    assert len(network["right_only"][0]["evidence"]) == 2
    assert (
        result["categories"]["certificate_metadata"]["right_only"][0]["values"][0]["verification"]
        == "not_performed"
    )
    right["manifest"]["permissions"] = []
    result = compare(left, right, Settings(_env_file=None, max_comparison_items=1))
    assert result["categories"]["permissions"]["output_truncated"]
    assert result["categories"]["permissions"]["counts"]["left_only"] == 2


def upload_run(client, app, case, xml=MANIFEST, adapter="static_review"):
    output = io.BytesIO()
    dex, _ = code_fixture()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest(xml))
        archive.writestr("classes.dex", dex)
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "compare.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": adapter},
    ).json()
    run_once(app.state.sessions, app.state.settings)
    return job


def pair(intake):
    client, app, _ = intake
    case = client.post("/api/v1/cases", json={"name": "APK comparison"}).json()["id"]
    left = upload_run(client, app, case)
    right = upload_run(
        client,
        app,
        case,
        MANIFEST.replace('android:debuggable="true"', 'android:debuggable="false"'),
    )
    return case, left, right


def test_comparison_endpoint_provenance_and_read_permissions(intake):
    client, app, _ = intake
    case, left, right = pair(intake)
    url = f"/api/v1/cases/{case}/comparisons"
    payload = {"left_job_id": left["id"], "right_job_id": right["id"]}
    response = client.post(url, json=payload)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["left"]["job_id"] == left["id"]
    assert data["left"]["result_sha256"]
    assert data["categories"]["application_flags"]["counts"]["changed"] == 1
    assert not data["same_input_sha256"] and "risk_score" not in data
    user = create_user(app.state.sessions, "compareviewer", "comparison-viewer-test-password")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "comparison-viewer-test-password"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    assert client.post(url, json=payload, headers=headers).status_code == 404
    assert (
        client.put(
            f"/api/v1/cases/{case}/members", json={"user_id": user.id, "role": "viewer"}
        ).status_code
        == 200
    )
    assert client.post(url, json=payload, headers=headers).status_code == 200
    other = client.post("/api/v1/cases", json={"name": "Another"}).json()["id"]
    assert client.post(f"/api/v1/cases/{other}/comparisons", json=payload).status_code == 404
    client.headers.pop("Authorization")
    assert client.post(url, json=payload).status_code == 401


@pytest.mark.parametrize(
    "mode",
    [
        "same_job",
        "pending",
        "different_adapter",
        "different_version",
        "tampered",
        "output_limit",
        "invalid_structure",
    ],
)
def test_invalid_comparisons_are_explicit(intake, mode):
    client, app, _ = intake
    case, left, right = pair(intake)
    expected = 409
    if mode == "same_job":
        right = left
        expected = 422
    elif mode == "output_limit":
        app.state.settings.max_comparison_bytes = 1024
        expected = 413
    else:
        with app.state.sessions.begin() as session:
            job = session.get(AnalysisJob, right["id"])
            if mode == "pending":
                job.status = "queued"
            elif mode == "different_adapter":
                job.adapter = "archive_inventory"
                expected = 422
            elif mode == "different_version":
                job.adapter_version = "0.0.1"
            elif mode == "invalid_structure":
                artifact = app.state.settings.evidence_root / job.result_key
                data = json.loads(artifact.read_bytes())
                data["manifest"].pop("application")
                raw = json.dumps(data).encode()
                artifact.write_bytes(raw)
                job.result_sha256 = hashlib.sha256(raw).hexdigest()
            else:
                (app.state.settings.evidence_root / job.result_key).write_bytes(b"altered")
    response = client.post(
        f"/api/v1/cases/{case}/comparisons",
        json={"left_job_id": left["id"], "right_job_id": right["id"]},
    )
    assert response.status_code == expected, response.text


def test_sample_specific_finding_ids_and_locations_do_not_define_api_equality():
    from test_static_review import observations

    from godeep.analysis.correlation.review import correlate

    left, right = observation(), observation()
    left["review"] = correlate(left["manifest"], observations(), "a" * 64, SETTINGS)
    right["review"] = correlate(right["manifest"], observations(), "b" * 64, SETTINGS)
    assert left["review"]["findings"][-1]["id"] != right["review"]["findings"][-1]["id"]
    result = compare(left, right, SETTINGS)
    assert result["categories"]["api_findings"]["counts"]["changed"] == 0
    for finding in right["review"]["findings"]:
        if finding["rule_id"].startswith("DEX."):
            finding["evidence_count"] += 1
    assert compare(left, right, SETTINGS)["categories"]["api_findings"]["counts"]["changed"] == 1
