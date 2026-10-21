"""Real binary XML/certificate parsing with original synthetic fixtures."""

import hashlib
import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import MANIFEST, binary_manifest, fixture_apk
from cryptography.hazmat.primitives import hashes

from godeep.analysis.static.manifest import parse_manifest
from godeep.core.config import Settings
from godeep.integrations.analyzers.common import AdapterFailure
from godeep.persistence.models import Sample
from godeep.services.auth import create_user
from godeep.workers.runner import run_once


def submit(client, raw):
    case_id = client.post("/api/v1/cases", json={"name": "Static fixture"}).json()["id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/samples",
        content=raw,
        headers={"X-Filename": "fixture.apk", "Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 201, response.text
    sample = response.json()
    queued = client.post(
        f"/api/v1/cases/{case_id}/analyses",
        json={"sample_id": sample["id"], "adapter": "android_static"},
    )
    assert queued.status_code == 202, queued.text
    return case_id, sample, queued.json()


def result(client, app, case_id, job):
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case_id}/analyses/{job['id']}"
    status = client.get(base).json()
    assert status["status"] == "completed", status
    response = client.get(base + "/result")
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_binary_manifest_pipeline_and_evidence_rules(intake):
    client, app, _ = intake
    raw, _ = fixture_apk()
    case_id, sample, job = submit(client, raw)
    data = result(client, app, case_id, job)
    manifest = data["manifest"]
    assert data["adapter"] == "android_static" and data["tool_versions"]["androguard"] == "4.1.4"
    assert manifest["source"]["format"] == "binary_axml"
    assert manifest["source"]["sha256"] == hashlib.sha256(binary_manifest()).hexdigest()
    assert manifest["identity"]["package_name"] == "org.godeep.fixture"
    assert manifest["identity"]["version_code_raw"] == "7"
    assert manifest["identity"]["application_label_raw"] == "@string/app_name"
    assert manifest["sdk"]["target_effective"] == 33
    assert manifest["permissions"][0]["capability_review"] == "sms"
    components = {c["type"]: c for c in manifest["components"]}
    assert components["service"]["name"] == "org.godeep.fixture.SyncService"
    assert components["service"]["exported_api17_plus"] is True
    assert components["provider"]["exported_api17_plus"] is False
    assert components["activity"]["launcher"] is True
    rules = manifest["findings"]
    assert {f["rule_id"] for f in rules} == {
        "MANIFEST.DEBUGGABLE",
        "MANIFEST.CLEARTEXT_DECLARED",
        "MANIFEST.BACKUP_DECLARED",
        "MANIFEST.EXPORTED_REVIEW",
    }
    assert all(f["requires_review"] and f["evidence"]["sha256"] for f in rules)
    assert not any("activity[" in f["evidence"]["selector"] for f in rules)
    assert data["coverage"]["dex_code"] == "not_analyzed" and "risk_score" not in data
    with app.state.sessions() as session:
        stored = session.get(Sample, sample["id"])
        assert (app.state.settings.evidence_root / stored.storage_key).read_bytes() == raw


@pytest.mark.parametrize("scheme", [None, "v2", "v3", "v31"])
def test_certificates_are_extracted_but_never_marked_verified(intake, scheme):
    client, app, _ = intake
    raw, certificate = fixture_apk(v1=scheme is None, signing_scheme=scheme)
    case_id, _, job = submit(client, raw)
    signing = result(client, app, case_id, job)["signing"]
    assert signing["cryptographic_verification"] == "not_performed"
    assert signing["coverage"] == "metadata_extraction_only", signing
    assert len(signing["certificates"]) == 1
    info = signing["certificates"][0]
    assert info["sha256"] == certificate.fingerprint(hashes.SHA256()).hex()
    assert info["verification"] == "not_performed"
    assert info["public_key_bits"] == 256 and info["subject_equals_issuer"] is True
    if scheme:
        assert signing["candidate_schemes"][scheme + "_block"] is True
    else:
        assert signing["candidate_schemes"]["v1_candidate_blocks"] == 1


def test_v31_only_block_reports_incomplete_extraction(intake):
    client, app, _ = intake
    raw, _ = fixture_apk(signing_scheme="v31_only")
    case_id, _, job = submit(client, raw)
    signing = result(client, app, case_id, job)["signing"]
    assert signing["candidate_schemes"]["v31_block"] is True
    assert signing["coverage"] == "partial"
    assert "v31_block_no_certificates" in signing["issues"]


def test_provider_legacy_default_and_explicit_override_note():
    xml = MANIFEST.replace('minSdkVersion="23"', 'minSdkVersion="15"').replace(
        'targetSdkVersion="33"', 'targetSdkVersion="16"'
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    provider = next(c for c in parsed["components"] if c["type"] == "provider")
    assert provider["exported_api17_plus"] is True
    assert provider["provider_api16_or_lower_override"] is True
    xml = xml.replace("android:authorities=", 'android:exported="false" android:authorities=')
    provider = next(
        c
        for c in parse_manifest(binary_manifest(xml), Settings(_env_file=None))["components"]
        if c["type"] == "provider"
    )
    assert provider["exported_api17_plus"] is False
    assert provider["provider_api16_or_lower_override"] is True


def test_sdk_defaults_and_missing_exported_are_not_guessed():
    xml = MANIFEST.replace(' android:targetSdkVersion="33"', "")
    parsed = parse_manifest(xml.encode(), Settings(_env_file=None))
    assert parsed["sdk"]["target_effective"] == 23
    assert parsed["sdk"]["target_defaulted_to_min"] is True
    xml = MANIFEST.replace(
        '<service android:name="SyncService" android:exported="true"/>',
        '<service android:name="SyncService"><intent-filter><action android:name="custom"/>'
        "</intent-filter></service>",
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    service = next(c for c in parsed["components"] if c["type"] == "service")
    assert service["exported_api17_plus"] is None
    assert any(f["rule_id"] == "MANIFEST.EXPORTED_REQUIRED" for f in parsed["findings"])


def test_inherited_permissions_disabled_components_and_resource_unknowns():
    xml = MANIFEST.replace("<application ", '<application android:permission="custom.GUARD" ')
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    assert not any(f["rule_id"] == "MANIFEST.EXPORTED_REVIEW" for f in parsed["findings"])
    xml = MANIFEST.replace(
        'android:exported="true"/>', 'android:enabled="false" android:exported="true"/>'
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    assert not any(f["rule_id"] == "MANIFEST.EXPORTED_REVIEW" for f in parsed["findings"])
    xml = MANIFEST.replace('targetSdkVersion="33"', 'targetSdkVersion="@integer/target"').replace(
        'android:exported="true"/>', 'android:exported="@bool/exposed"/>'
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    assert parsed["sdk"]["target_effective"] is None
    service = next(c for c in parsed["components"] if c["type"] == "service")
    assert service["exported_api17_plus"] is None


def test_alias_permission_inherits_target_activity_and_launcher_exemption_is_typed():
    xml = MANIFEST.replace(
        'android:name=".MainActivity"',
        'android:name=".MainActivity" android:permission="custom.GUARD"',
    )
    xml = xml.replace(
        "</application>",
        '<activity-alias android:name=".Alias" '
        'android:targetActivity=".MainActivity" android:exported="true"/></application>',
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    alias = next(c for c in parsed["components"] if c["type"] == "activity-alias")
    assert alias["permission_inherited"] == "custom.GUARD"
    xml = MANIFEST.replace(
        '<service android:name="SyncService" android:exported="true"/>',
        '<service android:name="SyncService" android:exported="true"><intent-filter>'
        '<action android:name="android.intent.action.MAIN"/>'
        '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></service>',
    )
    parsed = parse_manifest(binary_manifest(xml), Settings(_env_file=None))
    assert any(
        f["rule_id"] == "MANIFEST.EXPORTED_REVIEW" and "/service[" in f["evidence"]["selector"]
        for f in parsed["findings"]
    )


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"not XML", "manifest_parse_failed"),
        (
            b'<!DOCTYPE manifest [<!ENTITY x "expanded">]>'
            b'<manifest package="test"><application/></manifest>',
            "manifest_dtd_rejected",
        ),
        (b'<manifest package="test"><application/><application/></manifest>', "manifest_ambiguous"),
        (struct.pack("<HHI", 3, 8, 999), "manifest_parse_failed"),
    ],
)
def test_malformed_manifest_fails_job_with_explicit_code(intake, raw, code):
    client, app, _ = intake
    payload, _ = fixture_apk(manifest=raw)
    case_id, _, job = submit(client, payload)
    run_once(app.state.sessions, app.state.settings)
    status = client.get(f"/api/v1/cases/{case_id}/analyses/{job['id']}").json()
    assert status["status"] == "failed" and status["error_code"] == code


def test_manifest_and_certificate_limits_are_explicit(intake):
    client, app, _ = intake
    app.state.settings.max_manifest_bytes = 1024
    raw, _ = fixture_apk()
    case_id, _, job = submit(client, raw)
    run_once(app.state.sessions, app.state.settings)
    status = client.get(f"/api/v1/cases/{case_id}/analyses/{job['id']}").json()
    assert status["error_code"] == "member_size_exceeded"
    settings = Settings(_env_file=None, max_manifest_nodes=10)
    with pytest.raises(AdapterFailure):
        parse_manifest(binary_manifest(), settings)


def test_broken_certificate_container_is_partial_not_signature_invalid(intake):
    client, app, _ = intake
    raw, _ = fixture_apk()
    buffer = io.BytesIO(raw)
    with ZipFile(buffer, "a") as archive:
        archive.writestr("META-INF/BROKEN.RSA", b"not PKCS7")
    case_id, _, job = submit(client, buffer.getvalue())
    signing = result(client, app, case_id, job)["signing"]
    assert signing["coverage"] == "partial" and "v1_certificate_parse_error" in signing["issues"]
    assert signing["cryptographic_verification"] == "not_performed"


def test_static_result_is_case_scoped_and_readable_by_viewer(intake):
    client, app, _ = intake
    raw, _ = fixture_apk()
    case_id, _, job = submit(client, raw)
    result(client, app, case_id, job)
    viewer = create_user(app.state.sessions, "staticviewer", "static-viewer-password-123")
    token = client.post(
        "/api/v1/auth/login",
        json={"username": viewer.username, "password": "static-viewer-password-123"},
    ).json()["access_token"]
    headers = {"Authorization": "Bearer " + token}
    path = f"/api/v1/cases/{case_id}/analyses/{job['id']}/result"
    assert client.get(path, headers=headers).status_code == 404
    client.put(f"/api/v1/cases/{case_id}/members", json={"user_id": viewer.id, "role": "viewer"})
    assert client.get(path, headers=headers).status_code == 200


def test_analyzer_catalog_declares_real_capabilities(intake):
    client, _, _ = intake
    response = client.get("/api/v1/analyzers")
    assert response.status_code == 200
    catalog = {item["name"]: item for item in response.json()}
    assert set(catalog) == {
        "archive_inventory",
        "android_static",
        "dex_static",
        "dex_calls",
        "dex_graph",
        "dex_control_flow",
        "static_review",
        "signature_verify",
        "resource_inventory",
        "threat_review",
        "evasion_review",
        "risk_review",
        "library_review",
    }
    assert "binary_manifest" in catalog["android_static"]["capabilities"]
    assert not catalog["android_static"]["cryptographic_signature_verification"]
    client.headers.pop("Authorization")
    assert client.get("/api/v1/analyzers").status_code == 401


def test_oversized_signing_block_is_reported_as_partial(intake):
    client, app, _ = intake
    raw, _ = fixture_apk(signing_scheme="v2")
    modified = bytearray(raw)
    eocd = raw.rfind(b"PK\x05\x06")
    central = struct.unpack_from("<I", raw, eocd + 16)[0]
    struct.pack_into("<Q", modified, central - 24, 99999999)
    case_id, _, job = submit(client, bytes(modified))
    signing = result(client, app, case_id, job)["signing"]
    assert signing["apk_signing_block"] == "invalid_or_over_limit"
    assert signing["coverage"] == "partial"
    assert signing["cryptographic_verification"] == "not_performed"
