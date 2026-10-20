"""Offline-feed normalization, temporal validity and evidence-matching contracts."""

import copy
import hashlib
import io
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture

from godeep.analysis.correlation.intelligence import enrich
from godeep.core.config import Settings
from godeep.integrations.intelligence.local_feed import canonical, load_feed
from godeep.workers.runner import run_once

NOW = datetime(2026, 10, 20, tzinfo=UTC)


def feed_data(now=NOW):
    return {
        "schema_version": 1,
        "feed_id": "synthetic-test-feed",
        "source_name": "Original test fixtures",
        "published_at": (now - timedelta(hours=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
        "indicators": [
            {
                "id": "domain-1",
                "kind": "domain",
                "value": "EXAMPLE.ORG.",
                "classification": "suspicious",
                "confidence": "medium",
                "observed_at": (now - timedelta(hours=2)).isoformat(),
            }
        ],
    }


def configure(tmp_path, data=None, **overrides):
    path = tmp_path / "feed.json"
    raw = json.dumps(data or feed_data()).encode()
    path.write_bytes(raw)
    return Settings(
        _env_file=None,
        intel_feed_path=path,
        intel_feed_sha256=hashlib.sha256(raw).hexdigest(),
        **overrides,
    )


def candidate(value="example.org", kind="domain", index=0):
    return {
        "kind": kind,
        "value": value,
        "evidence": {"member": "classes.dex", "sha256": "a" * 64, "string_index": index},
    }


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain", "EXAMPLE.ORG.", "example.org"),
        ("ip", "2001:0db8::1", "2001:db8::1"),
        ("url", "HTTPS://EXAMPLE.ORG/A?x=Y", "https://example.org/A?x=Y"),
        ("apk_sha256", "A" * 64, "a" * 64),
    ],
)
def test_canonicalization_preserves_indicator_scope(kind, value, expected):
    assert canonical(kind, value) == expected


def test_exact_matching_dedup_and_source_claims(tmp_path):
    result = enrich(
        [candidate(), candidate(), candidate("sub.example.org")], configure(tmp_path), NOW
    )
    match = next(i for i in result["indicators"] if i["lookup_status"] == "matched")
    assert match["evidence_count"] == 1
    assert match["matches"][0]["classification"] == "suspicious"
    assert result["feed"]["source_name"] == "Original test fixtures"
    assert result["feed"]["network_requests"] == 0
    assert any(i["lookup_status"] == "no_match_in_local_feed" for i in result["indicators"])
    assert "risk_score" not in result and "malware_verdict" not in result


@pytest.mark.parametrize(
    "mode,status",
    [
        ("expired", "feed_expired"),
        ("stale", "feed_stale"),
        ("future", "feed_from_future"),
        ("invalid", "feed_invalid"),
    ],
)
def test_unusable_feeds_never_claim_no_match(tmp_path, mode, status):
    data = feed_data()
    if mode == "expired":
        data["valid_until"] = (NOW - timedelta(minutes=1)).isoformat()
    elif mode == "stale":
        data["published_at"] = (NOW - timedelta(days=31)).isoformat()
        data["indicators"][0]["observed_at"] = (NOW - timedelta(days=32)).isoformat()
    elif mode == "future":
        data["published_at"] = (NOW + timedelta(hours=1)).isoformat()
    else:
        data["indicators"][0]["kind"] = "unsupported"
    result = enrich([candidate()], configure(tmp_path, data), NOW)
    assert result["feed"]["status"] == status
    assert result["indicators"][0]["lookup_status"] == "not_checked"
    assert result["coverage"] == "not_checked"


def test_conflicting_and_expired_records_preserve_context(tmp_path):
    data = feed_data()
    second = copy.deepcopy(data["indicators"][0])
    second.update(id="domain-2", classification="benign")
    expired = copy.deepcopy(second)
    expired.update(id="domain-old", valid_until=(NOW - timedelta(minutes=1)).isoformat())
    data["indicators"] += [second, expired]
    result = enrich([candidate()], configure(tmp_path, data, max_intel_matches=1), NOW)
    match = result["indicators"][0]
    assert match["feed_assertions_conflict"]
    assert match["matches_truncated"] and len(match["matches"]) == 1
    assert match["active_match_count"] == 2 and match["expired_match_count"] == 1
    assert match["expired_match_ids"] == ["domain-old"]
    assert result["coverage"] == "partial"


def test_hash_schema_and_output_limits_are_explicit(tmp_path):
    settings = configure(
        tmp_path, max_intel_candidates=1, max_intel_matches=1, max_review_evidence=1
    )
    result = enrich([candidate(), candidate(index=1), candidate("example.net")], settings, NOW)
    assert result["coverage"] == "partial" and result["indicators"][0]["evidence_truncated"]
    settings.intel_feed_sha256 = "0" * 64
    assert load_feed(settings, NOW)["status"] == "feed_hash_mismatch"
    settings.intel_feed_sha256 = hashlib.sha256(b'{"feed_id":"a","feed_id":"b"}').hexdigest()
    settings.intel_feed_path.write_bytes(b'{"feed_id":"a","feed_id":"b"}')
    assert load_feed(settings, NOW)["status"] == "feed_invalid"
    assert (
        enrich([candidate()], Settings(_env_file=None), NOW)["feed"]["status"] == "not_configured"
    )


def test_feed_cli_validation_without_network(tmp_path):
    settings = configure(tmp_path, feed_data(datetime.now(UTC)))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "godeep.integrations.intelligence.local_feed",
            str(settings.intel_feed_path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    metadata = json.loads(result.stdout)
    assert metadata["status"] == "available" and "index" not in metadata


def test_threat_review_worker_matches_resource_iocs_with_case_scoping(intake, tmp_path):
    client, app, _ = intake
    config = configure(tmp_path, feed_data(datetime.now(UTC)))
    app.state.settings.intel_feed_path = config.intel_feed_path
    app.state.settings.intel_feed_sha256 = config.intel_feed_sha256
    dex, _ = code_fixture()
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", dex)
        archive.writestr("assets/config.json", b'{"endpoint":"https://example.org/path"}')
    case = client.post("/api/v1/cases", json={"name": "Threat review"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "threat.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201, sample.text
    queued = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "threat_review"},
    )
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert "intel_feed_path" not in job["config"] and "intel_feed_sha256" not in job["config"]
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["adapter"] == "threat_review"
    assert data["intelligence"]["feed"]["status"] == "available"
    match = next(i for i in data["intelligence"]["indicators"] if i["lookup_status"] == "matched")
    assert (
        match["value"] == "example.org" and match["evidence"][0]["member"] == "assets/config.json"
    )
    assert data["coverage"]["dynamic"] == "not_analyzed"
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404


@pytest.mark.parametrize("mode", ["duplicate_id", "naive_time", "boolean_schema", "extra_field"])
def test_invalid_feed_contract_is_rejected(tmp_path, mode):
    data = feed_data()
    if mode == "duplicate_id":
        data["indicators"].append(copy.deepcopy(data["indicators"][0]))
    elif mode == "naive_time":
        data["published_at"] = "2026-10-19T23:00:00"
    elif mode == "boolean_schema":
        data["schema_version"] = True
    else:
        data["unexpected"] = "value"
    assert load_feed(configure(tmp_path, data), NOW)["status"] == "feed_invalid"


def test_expired_matches_size_and_missing_feed_are_not_clean(tmp_path):
    data = feed_data()
    data["indicators"][0]["valid_until"] = (NOW - timedelta(minutes=1)).isoformat()
    settings = configure(tmp_path, data, max_intel_feed_bytes=1024)
    result = enrich([candidate()], settings, NOW)
    assert result["indicators"][0]["lookup_status"] == "expired_indicators_only"
    assert result["indicators"][0]["matches"] == []
    settings.intel_feed_path.write_bytes(b" " * 2000)
    assert load_feed(settings, NOW)["status"] == "feed_size_limit"
    settings.intel_feed_path.unlink()
    assert load_feed(settings, NOW)["status"] == "feed_unavailable"
