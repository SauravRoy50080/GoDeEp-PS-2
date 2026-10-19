"""Correlation contracts and real case-scoped unified analysis."""

import copy
import io
from zipfile import ZipFile

import pytest
from android_fixtures import MANIFEST, binary_manifest
from test_dex_calls import code_fixture

from godeep.analysis.correlation.review import correlate
from godeep.analysis.static.manifest import parse_manifest
from godeep.core.config import Settings
from godeep.workers.runner import run_once

SETTINGS = Settings(_env_file=None)
SAMPLE = "a" * 64


def observations():
    target = {
        "method_index": 0,
        "class_descriptor": "Landroid/telephony/SmsManager;",
        "method_name": "sendTextMessage",
        "descriptor": "()V",
    }
    call = {
        "rule_id": "DEX.SMS_SEND",
        "target": target,
        "caller": {"method_index": 1},
        "byte_offset": 256,
        "evidence_state": "decoded_invoke_instruction",
    }
    reference = {"rule_id": "DEX.SMS_SEND", **target, "byte_offset": 112}
    return {
        "dex_files": [
            {
                "member": "classes.dex",
                "sha256": "b" * 64,
                "call_sites": [call],
                "api_references": [reference],
                "network_candidates": [
                    {
                        "kind": "url",
                        "value": "https://example.org",
                        "string_index": 0,
                        "byte_offset": 200,
                    }
                ],
            }
        ]
    }


def manifest(send=True):
    xml = (
        MANIFEST.replace("android.permission.READ_SMS", "android.permission.SEND_SMS")
        if send
        else MANIFEST
    )
    return parse_manifest(binary_manifest(xml), SETTINGS)


def sms_finding(result):
    return next(f for f in result["findings"] if f["rule_id"] == "DEX.SMS_SEND")


def test_permission_context_retains_qualifiers_and_is_not_a_grant():
    result = correlate(manifest(), observations(), SAMPLE, SETTINGS)
    finding = sms_finding(result)
    assert finding["permission_context"]["status"] == "related_declaration_observed"
    assert finding["permission_context"]["declarations"][0]["max_sdk_version_raw"] == "32"
    assert finding["evidence_state"] == "decoded_invoke_instruction"
    assert finding["evidence_count"] == 1  # Identifier suppressed when decoded call exists.
    assert finding["independent_confirmation"] == "not_established"
    assert "risk_score" not in result and "malware" not in result


def test_missing_permission_and_unavailable_manifest_are_distinct():
    result = correlate(manifest(False), observations(), SAMPLE, SETTINGS)
    assert sms_finding(result)["permission_context"]["status"] == "no_related_declaration_observed"
    result = correlate(None, observations(), SAMPLE, SETTINGS)
    assert sms_finding(result)["permission_context"]["status"] == "manifest_unavailable"


def test_reference_only_lead_stays_reference_only():
    dex = observations()
    dex["dex_files"][0]["call_sites"] = []
    item = sms_finding(correlate(manifest(), dex, SAMPLE, SETTINGS))
    assert item["evidence_state"] == "method_identifier_reference"
    assert item["evidence"][0]["kind"] == "method_identifier_reference"


def test_duplicate_observation_not_counted_twice_and_ids_are_stable():
    dex = observations()
    before = correlate(manifest(), dex, SAMPLE, SETTINGS)
    dex["dex_files"][0]["call_sites"] *= 2
    dex["dex_files"][0]["network_candidates"] *= 2
    after = correlate(manifest(), dex, SAMPLE, SETTINGS)
    assert before == after
    changed = correlate(manifest(), dex, "c" * 64, SETTINGS)
    assert sms_finding(after)["id"] != sms_finding(changed)["id"]
    assert after["network_candidates"][0]["reputation"] == "not_checked"


def test_evidence_and_finding_caps_produce_partial_coverage():
    dex = observations()
    second = copy.deepcopy(dex["dex_files"][0])
    second["member"] = "classes2.dex"
    dex["dex_files"].append(second)
    result = correlate(manifest(), dex, SAMPLE, Settings(_env_file=None, max_review_evidence=1))
    finding = sms_finding(result)
    assert finding["evidence_count"] == 2 and finding["evidence_truncated"]
    assert len(finding["evidence"]) == 1 and result["coverage"] == "partial_output_limit"
    result = correlate(manifest(), dex, SAMPLE, Settings(_env_file=None, max_review_findings=1))
    assert len(result["findings"]) == 1 and result["coverage"] == "partial_output_limit"


@pytest.mark.parametrize("mode", ["normal", "bad_manifest", "bad_dex"])
def test_worker_unified_review_retains_phase_coverage(intake, mode):
    client, app, _ = intake
    dex, _ = code_fixture()
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml", b"broken" if mode == "bad_manifest" else binary_manifest()
        )
        archive.writestr("classes.dex", b"bad dex" if mode == "bad_dex" else dex)
    case = client.post("/api/v1/cases", json={"name": "Unified review"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "review.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201, sample.text
    queued = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "static_review"},
    )
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert job["config"]["max_review_evidence"] == 50
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    response = client.get(base + "/result")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["adapter"] == "static_review"
    assert data["coverage"]["dynamic"] == "not_analyzed"
    assert data["signing"]["cryptographic_verification"] == "not_performed"
    if mode == "bad_manifest":
        assert data["manifest"] is None and data["coverage"]["manifest"]["status"] == "failed"
        assert data["dex"]["dex_files"][0]["call_sites"]
    elif mode == "bad_dex":
        assert data["manifest"] and data["coverage"]["dex"] == "partial"
        assert data["dex"]["dex_files"][0]["error_code"] == "dex_parse_failed"
    else:
        assert data["coverage"]["manifest"]["status"] == "parsed"
        assert data["coverage"]["dex"] == "call_sites_decoded"
        assert any(f["rule_id"] == "DEX.DEBUGGER_CHECK" for f in data["review"]["findings"])
    other = client.post("/api/v1/cases", json={"name": "Another case"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404
