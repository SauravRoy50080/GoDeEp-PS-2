"""Connected plan/preflight/bundle lifecycle and existing runtime intake handoff."""

import copy
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from zipfile import ZipFile

import pytest
from test_runtime_captures import trace
from test_sandbox_preflight import profile, server

from godeep.sandbox.workflow import (
    bundle,
    create_plan,
    digest,
    encode,
    main,
    prepare,
    validate_sources,
    verify_bundle,
)


def setup_files(tmp_path, port=5038):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"synthetic opaque APK bytes for hashing only")
    source = {
        "schema_version": 1,
        "report_type": "investigation_analysis_snapshot",
        "report_id": str(uuid4()),
        "case": {"id": str(uuid4())},
        "sample": {
            "id": str(uuid4()),
            "sha256": digest(apk.read_bytes()),
            "size_bytes": apk.stat().st_size,
        },
        "analyses": [
            {
                "adapter": "static_review",
                "adapter_version": "1.0.1",
                "data": {
                    "schema_version": 1,
                    "adapter": "static_review",
                    "adapter_version": "1.0.1",
                    "input_sha256": digest(apk.read_bytes()),
                    "manifest": {"identity": {"package_name": "org.example.fixture"}},
                },
            }
        ],
    }
    config = tmp_path / "profile.json"
    config.write_text(profile(port).model_dump_json(), encoding="utf-8")
    return apk, config, encode(source)


def prepared(tmp_path):
    with server() as (port, _):
        apk, config, report = setup_files(tmp_path, port)
        plan = create_plan(report, config)
        plan_raw = encode(plan)
        preparation = prepare(plan_raw, config, apk)
    data = trace(plan.input_sha256)
    data["package_name"] = plan.package_name
    data["source_run_id"] = str(plan.run_id)
    started = preparation.prepared_at.isoformat()
    data["started_at"] = data["ended_at"] = started
    for event in data["events"]:
        event["timestamp"] = started
    return plan_raw, encode(preparation), encode(data)


def test_plan_provenance_and_execution_is_not_authorized(tmp_path):
    apk, config, report = setup_files(tmp_path)
    plan = create_plan(report, config, duration=30, max_events=10)
    assert plan.input_sha256 == digest(apk.read_bytes())
    assert plan.profile_sha256 == digest(config.read_bytes())
    assert plan.source_report_sha256 == digest(report)
    assert plan.execution_authorization == "not_granted"
    assert plan.duration_seconds == 30 and plan.max_events == 10


@pytest.mark.parametrize("mode", ["missing", "conflict", "identity", "schema", "bounds"])
def test_bad_report_or_plan_bounds_are_rejected(tmp_path, mode):
    _, config, raw = setup_files(tmp_path)
    doc = json.loads(raw)
    if mode == "missing":
        doc["analyses"] = []
    elif mode == "conflict":
        doc["analyses"].append(copy.deepcopy(doc["analyses"][0]))
        doc["analyses"][1]["data"]["manifest"]["identity"]["package_name"] = "org.other.app"
    elif mode == "identity":
        doc["analyses"][0]["data"]["input_sha256"] = "a" * 64
    elif mode == "schema":
        doc["schema_version"] = True
    with pytest.raises(ValueError):
        create_plan(encode(doc), config, duration=301 if mode == "bounds" else 60)


@pytest.mark.parametrize("mode", ["apk", "profile", "stale"])
def test_prepare_rejects_mismatch_before_any_adb_query(tmp_path, mode):
    with server() as (port, requests):
        apk, config, raw = setup_files(tmp_path, port)
        plan = create_plan(raw, config)
        if mode == "apk":
            apk.write_bytes(b"changed")
        elif mode == "profile":
            config.write_bytes(config.read_bytes() + b" ")
        else:
            plan.created_at = datetime.now(UTC) - timedelta(days=2)
        with pytest.raises(ValueError):
            prepare(encode(plan), config, apk)
        assert requests == []


def test_blocked_preparation_retains_failure_without_execution(tmp_path):
    with server(values={"ro.kernel.qemu": b"0"}) as (port, _):
        apk, config, raw = setup_files(tmp_path, port)
        plan = create_plan(raw, config)
        result = prepare(encode(plan), config, apk)
    assert result.status == "blocked"
    assert result.preflight["reason"] == "emulator_marker_missing"
    assert result.execution_authorization == "not_granted"


def test_exact_bytes_deterministic_bundle_and_trace_handoff(tmp_path):
    plan, prep, raw = prepared(tmp_path)
    result = bundle(plan, prep, raw)
    assert result == bundle(plan, prep, raw)
    manifest, trace_raw = verify_bundle(result)
    assert trace_raw == raw
    assert manifest["files"]["trace.json"]["sha256"] == digest(raw)
    assert manifest["files"]["plan.json"]["sha256"] == digest(plan)
    assert manifest["attribution"] == "collector_asserted_not_verified"
    assert manifest["isolation"] == "not_verified"
    assert manifest["collection_status"] == "partial"


@pytest.mark.parametrize(
    "mode",
    [
        "plan_bytes",
        "blocked",
        "checks",
        "input",
        "package",
        "run",
        "freshness",
        "duration",
        "events",
        "streams",
        "observed",
        "preflight_time",
    ],
)
def test_inconsistent_sources_cannot_be_bundled(tmp_path, mode):
    plan, prep, raw = prepared(tmp_path)
    p, r, t = json.loads(plan), json.loads(prep), json.loads(raw)
    if mode == "plan_bytes":
        plan += b" "
    elif mode == "blocked":
        r["status"] = "blocked"
    elif mode == "checks":
        r["preflight"]["checks"] = []
    elif mode == "observed":
        r["preflight"]["checks"][-1]["observed"] = "wrong"
    elif mode == "preflight_time":
        r["preflight"]["checked_at"] = "2000-01-01T00:00:00+00:00"
    elif mode == "input":
        t["input_sha256"] = "a" * 64
    elif mode == "package":
        t["package_name"] = "org.other.app"
    elif mode == "run":
        t["source_run_id"] = "wrong"
    elif mode == "freshness":
        for key in ("started_at", "ended_at"):
            t[key] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        for event in t["events"]:
            event["timestamp"] = t["started_at"]
    elif mode == "duration":
        t["ended_at"] = (
            datetime.fromisoformat(t["started_at"]) + timedelta(seconds=301)
        ).isoformat()
    else:
        if mode == "events":
            p["max_events"] = 1
        else:
            p["requested_streams"] = ["process"]
        plan = encode(p)
        r["plan_sha256"] = digest(plan)
    with pytest.raises(ValueError):
        validate_sources(plan, encode(r), encode(t))


def test_bundle_tampering_extra_members_and_size_rejected(tmp_path):
    plan, prep, trace_raw = prepared(tmp_path)
    good = bundle(plan, prep, trace_raw)
    with ZipFile(io.BytesIO(good)) as archive:
        contents = {item.filename: archive.read(item) for item in archive.infolist()}
    for mode in ("trace", "metadata", "path"):
        changed = dict(contents)
        if mode == "trace":
            changed["trace.json"] += b" "
        elif mode == "metadata":
            value = json.loads(changed["manifest.json"])
            value["isolation"] = "verified"
            changed["manifest.json"] = encode(value)
        else:
            changed["../extra"] = b"no"
        output = io.BytesIO()
        with ZipFile(output, "w") as archive:
            for name, value in changed.items():
                archive.writestr(name, value)
        with pytest.raises(ValueError):
            verify_bundle(output.getvalue())
    for modified in (b"prefix" + good, good + b"suffix"):
        with pytest.raises(ValueError):
            verify_bundle(modified)
    with pytest.raises(ValueError):
        verify_bundle(b"x" * 3145729)


def test_cli_plan_prepare_bundle_verify_and_no_overwrite(tmp_path, capsys):
    with server() as (port, _):
        apk, config, report = setup_files(tmp_path, port)
        report_path = tmp_path / "report.json"
        report_path.write_bytes(report)
        plan_path, prep_path = tmp_path / "plan.json", tmp_path / "preparation.json"
        assert (
            main(
                [
                    "plan",
                    "--report",
                    str(report_path),
                    "--profile",
                    str(config),
                    "--output",
                    str(plan_path),
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    "prepare",
                    "--plan",
                    str(plan_path),
                    "--profile",
                    str(config),
                    "--apk",
                    str(apk),
                    "--output",
                    str(prep_path),
                ]
            )
            == 0
        )
    data = trace(json.loads(plan_path.read_bytes())["input_sha256"])
    data["source_run_id"] = json.loads(plan_path.read_bytes())["run_id"]
    data["started_at"] = data["ended_at"] = json.loads(prep_path.read_bytes())["prepared_at"]
    for event in data["events"]:
        event["timestamp"] = data["started_at"]
    trace_path, output = tmp_path / "trace.json", tmp_path / "bundle.zip"
    trace_path.write_bytes(encode(data))
    assert (
        main(
            [
                "bundle",
                "--plan",
                str(plan_path),
                "--preparation",
                str(prep_path),
                "--trace",
                str(trace_path),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    saved = output.read_bytes()
    assert (
        main(
            [
                "bundle",
                "--plan",
                str(plan_path),
                "--preparation",
                str(prep_path),
                "--trace",
                str(trace_path),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert output.read_bytes() == saved
    extracted = tmp_path / "verified-trace.json"
    assert main(["verify", "--bundle", str(output), "--trace-output", str(extracted)]) == 0
    assert extracted.read_bytes() == trace_path.read_bytes()
    assert "verified_in_bundle_scope" in capsys.readouterr().out


def test_verified_bundle_trace_imports_through_existing_case_api(intake, tmp_path):
    from test_connected_workflow import upload

    from godeep.persistence.models import Sample
    from godeep.workers.runner import run_once

    client, app, _ = intake
    case = client.post("/api/v1/cases", json={"name": "Bundle handoff"}).json()["id"]
    sample = upload(client, case)
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={
            "sample_id": sample["id"],
            "adapter": "static_review",
        },
    ).json()
    assert run_once(app.state.sessions, app.state.settings)
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}"
    report = client.post(prefix + "/reports", json={"job_ids": [job["id"]]}).json()
    original = client.get(prefix + f"/reports/{report['id']}/download").content
    with app.state.sessions() as session:
        saved = session.get(Sample, sample["id"])
        apk = app.state.settings.evidence_root / saved.storage_key
    with server() as (port, _):
        config = tmp_path / "actual-profile.json"
        config.write_text(profile(port).model_dump_json(), encoding="utf-8")
        plan = create_plan(original, config)
        preparation = prepare(encode(plan), config, apk)
    data = trace(plan.input_sha256)
    data["package_name"] = plan.package_name
    data["source_run_id"] = str(plan.run_id)
    data["started_at"] = data["ended_at"] = preparation.prepared_at.isoformat()
    for event in data["events"]:
        event["timestamp"] = data["started_at"]
    raw = encode(data)
    manifest, validated = verify_bundle(bundle(encode(plan), encode(preparation), raw))
    assert manifest["case_id"] == case and manifest["sample_id"] == sample["id"]
    assert validated == raw
    response = client.post(
        prefix + "/runtime-captures",
        content=validated,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
    snapshot = client.post(
        prefix + "/reports",
        json={
            "job_ids": [job["id"]],
            "capture_ids": [response.json()["id"]],
        },
    )
    assert snapshot.status_code == 201, snapshot.text
