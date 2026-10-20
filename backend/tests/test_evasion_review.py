"""Loading/evasion leads retain static evidence and never imply malicious intent."""

import copy
import io
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture

from godeep.analysis.correlation.evasion import RULES, review
from godeep.core.config import Settings
from godeep.workers.runner import run_once

SETTINGS = Settings(_env_file=None)


def sources(rule="DEX.DEBUGGER_CHECK"):
    target = {
        "method_index": 0,
        "class_descriptor": "Landroid/os/Debug;",
        "method_name": "isDebuggerConnected",
        "descriptor": "()Z",
    }
    reference = {"rule_id": rule, **target, "byte_offset": 112}
    call = {"rule_id": rule, "target": target, "caller": {"method_index": 1}, "byte_offset": 256}
    dex = {
        "coverage": "call_sites_decoded",
        "dex_files": [
            {
                "member": "classes.dex",
                "sha256": "b" * 64,
                "call_sites": [call],
                "api_references": [reference],
            }
        ],
    }
    resources = {"coverage": "no_selected_members", "files": []}
    return dex, resources


@pytest.mark.parametrize("rule", list(RULES))
def test_allowlist_preserves_evidence_and_benign_context(rule):
    dex, resources = sources(rule)
    result = review(dex, resources, "a" * 64, SETTINGS)
    finding = result["findings"][0]
    assert finding["category"] == RULES[rule][0]
    assert finding["evidence_count"] == 1  # Identifier and call are not independent evidence.
    assert finding["strongest_evidence"] == "decoded_invoke_instruction"
    assert finding["evidence"][0]["byte_offset"] == 256
    assert finding["evidence"][0]["caller"]["method_index"] == 1
    assert finding["benign_explanation"] and finding["requires_review"]
    assert result["coverage"] == "selected_rules_applied"
    assert "risk_score" not in result and "malware" not in result
    assert "anti_emulation" in result["not_evaluated"]


def test_identifier_only_and_unrelated_rules():
    dex, resources = sources()
    dex["dex_files"][0]["call_sites"] = []
    result = review(dex, resources, "a" * 64, SETTINGS)
    assert result["findings"][0]["strongest_evidence"] == "method_identifier_reference"
    dex, resources = sources("DEX.SMS_SEND")
    assert not review(dex, resources, "a" * 64, SETTINGS)["findings"]


def test_deduplication_caps_and_partial_coverage():
    dex, resources = sources()
    call = dex["dex_files"][0]["call_sites"][0]
    dex["dex_files"][0]["call_sites"].extend([copy.deepcopy(call), {**call, "byte_offset": 300}])
    resources["coverage"] = "partial"
    result = review(dex, resources, "a" * 64, Settings(_env_file=None, max_review_evidence=1))
    finding = result["findings"][0]
    assert finding["evidence_count"] == 2 and len(finding["evidence"]) == 1
    assert finding["evidence_truncated"] and result["output_limited"]
    assert result["coverage"] == "partial"
    dex["coverage"] = "failed"
    assert (
        review(dex, {"coverage": "no_selected_members"}, "a" * 64, SETTINGS)["coverage"]
        == "partial"
    )


def test_header_candidates_are_unlinked_and_bounded():
    dex = {"coverage": "call_sites_decoded", "dex_files": []}
    files = [
        {"member": "assets/" + str(i), "sha256": str(i) * 64, "format": fmt}
        for i, fmt in enumerate(
            ["embedded_dex_candidate", "embedded_zip_candidate", "elf_candidate"]
        )
    ]
    resources = {"coverage": "selected_members_inspected", "files": files}
    result = review(dex, resources, "a" * 64, SETTINGS)
    assert {f["category"] for f in result["findings"]} == {
        "embedded_dex",
        "embedded_archive",
        "native_binary",
    }
    assert all(f["strongest_evidence"] == "file_header_candidate" for f in result["findings"])
    result = review(dex, resources, "a" * 64, Settings(_env_file=None, max_review_findings=1))
    assert len(result["findings"]) == 1 and result["output_limited"]
    assert result["coverage"] == "partial"


def test_ids_are_deterministic_and_input_scoped():
    dex, resources = sources()
    first = review(dex, resources, "a" * 64, SETTINGS)
    assert first == review(dex, resources, "a" * 64, SETTINGS)
    assert (
        first["findings"][0]["id"]
        != review(dex, resources, "c" * 64, SETTINGS)["findings"][0]["id"]
    )


def test_real_worker_catalog_case_scope_and_forensic_report(intake):
    client, app, _ = intake
    catalog = client.get("/api/v1/analyzers").json()
    adapter = next(item for item in catalog if item["name"] == "evasion_review")
    assert adapter["apk_execution"] is False and adapter["malware_classification"] is False
    case = client.post("/api/v1/cases", json={"name": "Loading review"}).json()["id"]
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", code_fixture()[0])
        archive.writestr("assets/plugin.bin", b"dex\n035\0" + bytes(112))
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=buffer.getvalue(),
        headers={"X-Filename": "review.apk", "Content-Type": "application/octet-stream"},
    ).json()["id"]
    job = client.post(
        f"/api/v1/cases/{case}/analyses", json={"sample_id": sample, "adapter": "evasion_review"}
    )
    assert job.status_code == 202, job.text
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job.json()['id']}"
    assert client.get(base).json()["status"] == "completed"
    result = client.get(base + "/result").json()["data"]
    assert {f["category"] for f in result["evasion_review"]["findings"]} == {
        "debugger_check",
        "embedded_dex",
    }
    assert result["coverage"]["dynamic"] == "not_analyzed"
    report = client.post(
        f"/api/v1/cases/{case}/samples/{sample}/reports", json={"job_ids": [job.json()["id"]]}
    )
    assert report.status_code == 201, report.text
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert (
        client.get(f"/api/v1/cases/{other}/analyses/{job.json()['id']}/result").status_code == 404
    )
