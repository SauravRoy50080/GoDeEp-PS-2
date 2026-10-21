"""Offline MISP subset conversion, reproducible provenance and real worker handoff."""

import copy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from test_network_correlation import setup as report_setup

from godeep.core.config import Settings
from godeep.integrations.intelligence import misp_export as misp
from godeep.integrations.intelligence.local_feed import load_feed
from godeep.workers.runner import run_once

NOW = datetime(2026, 10, 22, 10, tzinfo=UTC)


def attribute(kind="domain", value="Example.org.", **updates):
    return {
        "uuid": str(uuid4()),
        "type": kind,
        "value": value,
        "timestamp": str(int(NOW.timestamp())),
        "to_ids": True,
        "deleted": False,
        "disable_correlation": False,
        **updates,
    }


def event(*attributes, **updates):
    return {
        "Event": {
            "uuid": str(uuid4()),
            "published": True,
            "timestamp": str(int(NOW.timestamp())),
            "Attribute": list(attributes) or [attribute()],
            **updates,
        }
    }


def policy(**updates):
    return misp.Policy(
        feed_id="synthetic-misp",
        source_name="Synthetic MISP fixture",
        source_url="https://misp.example.org",
        published_at=NOW,
        **updates,
    )


def output(data, **updates):
    raw = misp.encode(data)
    feed, receipt = misp.convert(raw, policy(**updates))
    return misp.decode(feed), misp.decode(receipt)


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("domain", "EXAMPLE.org.", [("domain", "example.org")]),
        ("hostname", "a.example.org", [("domain", "a.example.org")]),
        ("url", "HTTPS://EXAMPLE.org/a?b=1", [("url", "https://example.org/a?b=1")]),
        ("ip-src", "2001:0db8::1", [("ip", "2001:db8::1")]),
        ("ip-dst", "192.0.2.1", [("ip", "192.0.2.1")]),
        ("domain|ip", "example.org|192.0.2.1", [("domain", "example.org"), ("ip", "192.0.2.1")]),
        ("ip-dst|port", "2001:db8::1|443", [("ip", "2001:db8::1")]),
        ("ip-src|port", "192.0.2.1|53", [("ip", "192.0.2.1")]),
        ("hostname|port", "example.org|8443", [("domain", "example.org")]),
        ("sha256", "A" * 64, [("apk_sha256", "a" * 64)]),
        ("filename|sha256", "sample.bin|" + "A" * 64, [("apk_sha256", "a" * 64)]),
        ("x509-fingerprint-sha256", "B" * 64, [("certificate_sha256", "b" * 64)]),
    ],
)
def test_supported_mappings(kind, value, expected):
    assert misp.mapped(kind, value) == expected


def test_deterministic_policy_default_unknown_and_exact_provenance():
    data = event(attribute(), attribute("sha256", "a" * 64))
    raw = misp.encode(data)
    first = misp.convert(raw, policy())
    assert first == misp.convert(raw, policy())
    feed, receipt = map(misp.decode, first)
    assert all(
        row["classification"] == row["confidence"] == "unknown" for row in feed["indicators"]
    )
    assert receipt["source"]["sha256"] == misp.digest(raw)
    assert receipt["feed"]["sha256"] == misp.digest(first[0])
    for row in receipt["provenance"]:
        assert row["snapshot_pointer"].startswith("/Event/Attribute/")
        assert row["timestamp_basis"] == "misp_attribute_last_modified"
        assert row["classification_basis"] == "operator_policy_not_misp_detection_flag"
    assert receipt["network_requests"] == 0 and receipt["coverage"] == "partial_misp_format_subset"


def test_response_envelope_objects_and_deleted_object_filtering():
    first = event()
    first["Event"]["Object"] = [
        {"deleted": False, "Attribute": [attribute("ip-dst", "192.0.2.2")]},
        {"deleted": True, "Attribute": [attribute()]},
    ]
    feed, receipt = output({"response": [first, event()]})
    assert len(feed["indicators"]) == 3
    assert receipt["exclusion_counts"] == {"deleted_object": 1}
    assert any("/Object/0/Attribute/0" in row["snapshot_pointer"] for row in receipt["provenance"])


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"deleted": True}, "deleted_attribute"),
        ({"disable_correlation": "1"}, "disabled_attribute"),
        ({"to_ids": 0}, "non_detection_attribute"),
        ({"to_ids": "true"}, "invalid_boolean_flag"),
        ({"timestamp": str(int((NOW - timedelta(days=31)).timestamp()))}, "stale_attribute"),
        (
            {"timestamp": str(int((NOW + timedelta(seconds=1)).timestamp()))},
            "attribute_timestamp_from_future",
        ),
        ({"type": "md5", "value": "a" * 32}, "unsupported_attribute_type"),
        ({"type": "ip-dst", "value": "192.0.2.0/24"}, "scoped_or_cidr_ip_unsupported"),
        ({"uuid": "invalid"}, "invalid_attribute_uuid"),
    ],
)
def test_exclusions_are_visible_and_do_not_emit_fake_records(changes, reason):
    feed, receipt = output(event(attribute(**changes)))
    assert feed["indicators"] == []
    assert receipt["status"] == "no_eligible_indicators"
    assert receipt["exclusion_counts"] == {reason: 1}


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"published": False}, "unpublished_event"),
        ({"deleted": True}, "deleted_event"),
        ({"disable_correlation": True}, "disabled_event"),
    ],
)
def test_event_filters(changes, reason):
    _, receipt = output(event(**changes))
    assert receipt["exclusion_counts"] == {reason: 1}


def test_expiry_is_bounded_by_age_and_policy_not_renewed_indefinitely():
    modified = NOW - timedelta(days=29, hours=23)
    feed, _ = output(event(attribute(timestamp=str(int(modified.timestamp())))), valid_hours=48)
    assert datetime.fromisoformat(feed["indicators"][0]["valid_until"]) == NOW + timedelta(hours=1)


@pytest.mark.parametrize(
    "mode",
    [
        "duplicate_event",
        "duplicate_attribute",
        "duplicate_key",
        "bad_shape",
        "future_event",
        "event_boolean",
        "nonfinite",
    ],
)
def test_structural_ambiguity_rejects_complete_conversion(mode):
    data = event()
    if mode == "duplicate_event":
        data = {"response": [data, copy.deepcopy(data)]}
    elif mode == "duplicate_attribute":
        data["Event"]["Attribute"] *= 2
    elif mode == "bad_shape":
        data = {"Attribute": []}
    elif mode == "future_event":
        data["Event"]["timestamp"] = str(int(NOW.timestamp()) + 1)
    elif mode == "event_boolean":
        data["Event"]["published"] = "yes"
    raw = misp.encode(data)
    if mode == "duplicate_key":
        raw = b'{"Event":{},"Event":{}}'
    elif mode == "nonfinite":
        raw = b'{"Event":NaN}'
    with pytest.raises((ValueError, KeyError, TypeError)):
        misp.convert(raw, policy())


@pytest.mark.parametrize("mode", ["attribute", "object", "event", "source", "feed", "receipt"])
def test_budgets_abort_before_publishing(mode, monkeypatch):
    data = event(attribute(), attribute())
    if mode == "attribute":
        monkeypatch.setattr(misp, "ATTRIBUTE_LIMIT", 1)
    elif mode == "object":
        data["Event"]["Object"] = [{"Attribute": []}]
        monkeypatch.setattr(misp, "OBJECT_LIMIT", 0)
    elif mode == "event":
        monkeypatch.setattr(misp, "EVENT_LIMIT", 0)
    elif mode == "source":
        monkeypatch.setattr(misp, "SOURCE_LIMIT", 10)
    elif mode == "feed":
        monkeypatch.setattr(misp, "FEED_LIMIT", 10)
    else:
        monkeypatch.setattr(misp, "RECEIPT_LIMIT", 10)
    with pytest.raises(ValueError):
        misp.convert(misp.encode(data), policy())


@pytest.mark.parametrize("mode", ["source", "feed", "receipt", "extra"])
def test_package_replay_integrity_and_existing_directory_refusal(tmp_path, mode):
    source = tmp_path / "export.json"
    source.write_bytes(misp.encode(event()))
    directory = tmp_path / "package"
    misp.write_package(source, policy(), directory)
    assert misp.verify(directory)["status"] == "converted"
    with pytest.raises(FileExistsError):
        misp.write_package(source, policy(), directory)
    if mode == "extra":
        (directory / "extra").write_text("unexpected")
    else:
        path = directory / (mode + ".json")
        if mode == "receipt":
            receipt = misp.decode(path.read_bytes())
            receipt["summary"]["events"] = 99
            path.write_bytes(misp.encode(receipt))
        else:
            path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        misp.verify(directory)


def test_feed_handoff_uses_existing_hash_and_expiry_guards(tmp_path):
    source = tmp_path / "export.json"
    source.write_bytes(misp.encode(event()))
    receipt = misp.write_package(source, policy(), tmp_path / "package")
    settings = Settings(
        _env_file=None,
        intel_feed_path=tmp_path / "package/feed.json",
        intel_feed_sha256=receipt["feed"]["sha256"],
    )
    assert load_feed(settings, NOW)["status"] == "available"
    assert load_feed(settings, NOW + timedelta(days=2))["status"] == "feed_expired"
    settings.intel_feed_sha256 = "f" * 64
    assert load_feed(settings, NOW)["status"] == "feed_hash_mismatch"


def test_cli_conversion_verification_and_sanitized_errors(tmp_path, capsys):
    source = tmp_path / "export.json"
    source.write_bytes(misp.encode(event()))
    directory = tmp_path / "package"
    assert (
        misp.main(
            [
                "convert",
                "--source",
                str(source),
                "--output-dir",
                str(directory),
                "--feed-id",
                "test",
                "--source-name",
                "Synthetic",
                "--source-url",
                "https://misp.example.org",
                "--published-at",
                NOW.isoformat(),
            ]
        )
        == 0
    )
    assert misp.main(["verify", "--directory", str(directory)]) == 0
    assert "example.org" not in capsys.readouterr().out  # CLI metadata does not print indicators.
    assert misp.main(["verify", "--directory", str(tmp_path / "missing")]) == 2
    assert "misp_conversion_or_verification_failed" in capsys.readouterr().out


def test_imported_feed_through_real_worker_forensic_report_and_review(intake, tmp_path):
    client, app, _ = intake
    case, sample, _, _, uri = report_setup(intake)
    now = datetime.now(UTC)
    data = event(attribute("sha256", sample["sha256"], timestamp=str(int(now.timestamp()))))
    data["Event"]["timestamp"] = str(int(now.timestamp()))
    source = tmp_path / "misp.json"
    source.write_bytes(misp.encode(data))
    config = policy().model_copy(update={"published_at": now})
    receipt = misp.write_package(source, config, tmp_path / "imported")
    misp.verify(tmp_path / "imported")
    app.state.settings.intel_feed_path = tmp_path / "imported/feed.json"
    app.state.settings.intel_feed_sha256 = receipt["feed"]["sha256"]
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample["id"], "adapter": "threat_review"},
    ).json()
    assert run_once(app.state.sessions, app.state.settings)
    result = client.get(f"/api/v1/cases/{case}/analyses/{job['id']}/result")
    assert result.status_code == 200, result.text
    intel = result.json()["data"]["intelligence"]
    assert intel["feed"]["feed_sha256"] == receipt["feed"]["sha256"]
    match = next(row for row in intel["indicators"] if row["kind"] == "apk_sha256")
    assert (
        match["lookup_status"] == "matched" and match["matches"][0]["classification"] == "unknown"
    )
    prefix = uri.rsplit("/", 1)[0]
    report = client.post(prefix, json={"job_ids": [job["id"]]}).json()
    report_uri = prefix + "/" + report["id"]
    assert (
        client.get(report_uri + "/download").json()["analyses"][0]["data"]["intelligence"] == intel
    )
    note = client.post(
        report_uri + "/reviews",
        json={
            "expected_report_sha256": report["artifact_sha256"],
            "decision": "follow_up",
            "text": "Exact imported hash claim; classification remains unknown",
            "evidence_references": [
                {
                    "source_kind": "analysis",
                    "source_id": job["id"],
                    "pointer": "/analyses/0/data/intelligence/indicators",
                }
            ],
        },
    )
    assert note.status_code == 201, note.text
