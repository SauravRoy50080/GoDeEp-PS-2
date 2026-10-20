"""Policy arithmetic, duplicate resistance, coverage and real offline worker flow."""

import copy
import io
from datetime import UTC, datetime
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture
from test_threat_intelligence import configure, feed_data

from godeep.analysis.correlation.risk import CAPS, WEIGHTS, prioritize
from godeep.workers.runner import run_once


def source(findings=None):
    return {
        "review": {"findings": findings or []},
        "coverage": {
            "manifest": {"status": "parsed"},
            "dex": "call_sites_decoded",
            "correlation": "available_observations_grouped",
            "resources": "no_selected_members",
        },
        "intelligence": {
            "feed": {"status": "available", "feed_sha256": "f" * 64},
            "coverage": "local_exact_matching_complete",
            "indicators": [],
        },
    }


def finding(rule="DEX.DYNAMIC_LOADING", state="decoded_invoke_instruction", identity="fixture"):
    return {
        "rule_id": rule,
        "id": identity,
        "evidence_state": state,
        "evidence": [{"member": "classes.dex", "byte_offset": 256}],
    }


def assertion(labels, **extra):
    return {
        "kind": "domain",
        "value": "example.org",
        "lookup_status": "matched",
        "matches": [
            {"id": str(index), "classification": label} for index, label in enumerate(labels)
        ],
        **extra,
    }


def test_zero_is_not_safety_and_dynamic_remains_unassessed():
    result = prioritize(source())
    assert result["score"] == 0 and result["priority"] == "routine"
    assert result["calibration"] == "not_calibrated" and not result["assessment_complete"]
    assert "dynamic_not_analyzed" in result["coverage_gaps"]
    assert not result["contributions"]


def test_reference_weight_is_lower_and_duplicates_do_not_accumulate():
    reference = finding(state="method_identifier_reference")
    assert prioritize(source([reference]))["score"] == 2
    decoded = finding(identity="decoded")
    result = prioritize(source([reference, decoded, decoded, copy.deepcopy(decoded)]))
    assert result["score"] == 10
    assert result["contributions"][0]["source_finding_ids"] == ["decoded", "fixture"]


def test_caps_and_explanations_reconcile_exactly():
    findings = [
        finding(
            rule,
            "static_indicator" if rule.startswith("MANIFEST.") else "decoded_invoke_instruction",
            rule,
        )
        for rule in WEIGHTS
    ]
    data = source(findings)
    data["intelligence"]["indicators"] = [assertion(["malicious"])]
    result = prioritize(data)
    assert result["score"] == 100 and result["priority"] == "high"
    assert result["category_totals"] == CAPS
    assert sum(c["awarded_points"] for c in result["contributions"]) == result["score"]
    assert any(c["awarded_points"] < c["requested_points"] for c in result["contributions"])
    assert all(c["reason"] for c in result["contributions"])


@pytest.mark.parametrize(
    "labels,expected",
    [(["benign"], 0), (["suspicious"], 20), (["malicious"], 40), (["benign", "malicious"], 0)],
)
def test_feed_labels_are_source_claims_and_conflicts_are_excluded(labels, expected):
    data = source()
    data["intelligence"]["indicators"] = [assertion(labels), assertion(labels)]
    result = prioritize(data)
    assert result["score"] == expected  # Repeated matches never sum.
    if "benign" in labels and "malicious" in labels:
        assert len(result["excluded_intelligence"]) == 2


@pytest.mark.parametrize(
    "status,lookup",
    [
        ("stale", "matched"),
        ("available", "expired_indicators_only"),
        ("not_configured", "not_checked"),
    ],
)
def test_unavailable_or_expired_feed_adds_no_points(status, lookup):
    data = source()
    data["intelligence"]["feed"]["status"] = status
    data["intelligence"]["indicators"] = [assertion(["malicious"], lookup_status=lookup)]
    assert prioritize(data)["score"] == 0


def test_unknown_rules_missing_evidence_and_permissions_do_not_score():
    empty = finding()
    empty["evidence"] = []
    data = source([finding("CUSTOM.MALWARE"), finding("DEX.SMS_SEND", "unknown"), empty])
    data["manifest"] = {"permissions": [{"name": "android.permission.SEND_SMS"}]}
    assert prioritize(data)["score"] == 0


def test_partial_coverage_changes_gaps_without_subtracting_points():
    data = source([finding()])
    initial = prioritize(data)
    data["coverage"] = {}
    data["intelligence"]["coverage"] = "not_checked"
    result = prioritize(data)
    assert result["score"] == initial["score"]
    assert len(result["coverage_gaps"]) > len(initial["coverage_gaps"])
    assert result == prioritize(data)


def test_risk_worker_pinned_feed_evidence_reports_and_case_scope(intake, tmp_path):
    client, app, _ = intake
    config = configure(tmp_path, feed_data(datetime.now(UTC)))
    app.state.settings.intel_feed_path = config.intel_feed_path
    app.state.settings.intel_feed_sha256 = config.intel_feed_sha256
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", code_fixture()[0])
        archive.writestr("assets/config.json", b'{"endpoint":"https://example.org/path"}')
    case = client.post("/api/v1/cases", json={"name": "Priority"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "priority.apk", "Content-Type": "application/octet-stream"},
    ).json()["id"]
    queued = client.post(
        f"/api/v1/cases/{case}/analyses", json={"sample_id": sample, "adapter": "risk_review"}
    )
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert "intel_feed_path" not in job["config"]
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["intelligence"]["feed"]["status"] == "available"
    contribution = next(
        c for c in data["risk_review"]["contributions"] if c["category"] == "intelligence"
    )
    assert contribution["awarded_points"] == 20
    assert contribution["feed_sha256"] == config.intel_feed_sha256
    assert contribution["indicator_references"][0]["value"] == "example.org"
    ids = {f["id"] for f in data["review"]["findings"]}
    assert all(set(c["source_finding_ids"]) <= ids for c in data["risk_review"]["contributions"])
    assert data["coverage"]["risk_scoring"] == "uncalibrated_static_priority_policy"
    report = client.post(
        f"/api/v1/cases/{case}/samples/{sample}/reports", json={"job_ids": [job["id"]]}
    )
    assert report.status_code == 201, report.text
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404
