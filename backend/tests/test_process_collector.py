"""Passive sampler parsing, real TCP requests, bounded artifacts and runtime handoff."""

import json
from contextlib import contextmanager
from datetime import timedelta

import pytest
from test_sandbox_preflight import packet, profile, server
from test_sandbox_workflow import setup_files

from godeep.sandbox import collector
from godeep.sandbox.adb import AdbProbe
from godeep.sandbox.collector import collect, main, processes, verify
from godeep.sandbox.workflow import create_plan, digest, encode
from godeep.schemas.runtime_captures import decode_trace

PS = "shell,v2,raw:ps -A -o PID,NAME"
TABLE = (
    b"  PID NAME\n  1 init\n 123 org.example.fixture\n"
    b" 124 org.example.fixture:worker\n 125 org.example.fixture.other\n"
)


@contextmanager
def setup(tmp_path, reply=None, values=None, max_events=100):
    reply = b"OKAY" + packet(1, TABLE) + packet(3, b"\0") if reply is None else reply
    with server(faults={PS: reply}, values=values) as (port, requests):
        apk, config, report = setup_files(tmp_path, port)
        plan = create_plan(report, config, duration=1, max_events=max_events)
        yield plan, apk, config, requests


def test_name_selection_subprocesses_and_sorted_pids():
    assert processes(TABLE, "org.example.fixture") == [
        (123, "org.example.fixture"),
        (124, "org.example.fixture:worker"),
    ]
    assert processes(b"PID NAME\n1 init\n", "org.example.fixture") == []


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"PID CMD\n1 app",
        b"PID NAME\ninvalid",
        b"PID NAME\n0 app",
        b"PID NAME\n2147483648 app",
        b"PID NAME\n1 init\n1 app",
        b"PID NAME\n1 \xff",
    ],
)
def test_invalid_tables_do_not_publish_partial_snapshot(raw):
    with pytest.raises(ValueError):
        processes(raw, "org.example.fixture")


def test_real_tcp_process_command_preserves_exact_stdout(tmp_path):
    with setup(tmp_path) as (plan, _, _, requests):
        assert AdbProbe(plan.profile).process_snapshot() == TABLE
    assert requests == ["host:transport:emulator-5554", PS]


def test_sampler_completed_window_repeated_presence_and_receipt(tmp_path):
    with setup(tmp_path) as (plan, apk, config, _):
        result = collect(encode(plan), config, apk, tmp_path / "run", interval=0.2)
    assert result["collection_status"] == "completed"
    assert result == verify(tmp_path / "run")
    trace = decode_trace((tmp_path / "run/trace.json").read_bytes())
    assert len(trace.events) >= 2 and all(event.action == "observed" for event in trace.events)
    assert trace.coverage.process == "partial" and trace.coverage.network == "not_collected"
    journal = json.loads((tmp_path / "run/observations.json").read_bytes())
    assert journal["absence_inference"] == "not_performed"
    assert all(item["raw_sha256"] == digest(TABLE) for item in journal["observations"])
    assert trace.ended_at - trace.started_at <= timedelta(seconds=1)


@pytest.mark.parametrize("limit", ["events", "snapshots", "raw"])
def test_collection_limits_remain_explicit_and_verifiable(tmp_path, monkeypatch, limit):
    if limit == "snapshots":
        monkeypatch.setattr(collector, "MAX_SNAPSHOTS", 1)
    elif limit == "raw":
        monkeypatch.setattr(collector, "MAX_RAW", 1)
    with setup(tmp_path, max_events=1 if limit == "events" else 100) as (plan, apk, config, _):
        result = collect(encode(plan), config, apk, tmp_path / "limited", interval=0.1)
    assert result["collection_status"] in {"partial", "failed"}
    assert verify(tmp_path / "limited") == result
    journal = json.loads((tmp_path / "limited/observations.json").read_bytes())
    assert (
        journal["termination_reason"]
        == {"events": "event_limit", "snapshots": "snapshot_limit", "raw": "raw_output_limit"}[
            limit
        ]
    )


@pytest.mark.parametrize(
    "reply",
    [
        b"FAIL0004oops",
        b"OKAY" + packet(3, b"\1"),
        b"OKAY" + packet(1, b"PID CMD\n") + packet(3, b"\0"),
    ],
)
def test_failed_queries_preserve_failure_and_no_fake_processes(tmp_path, reply):
    with setup(tmp_path, reply=reply) as (plan, apk, config, _):
        result = collect(encode(plan), config, apk, tmp_path / "failed", interval=0.1)
    assert result["collection_status"] == "failed"
    assert result == verify(tmp_path / "failed")
    trace = decode_trace((tmp_path / "failed/trace.json").read_bytes())
    assert trace.events == [] and trace.coverage.process == "not_collected"


def test_blocked_preflight_makes_no_trace_or_process_request(tmp_path):
    with setup(tmp_path, values={"ro.kernel.qemu": b"0"}) as (plan, apk, config, requests):
        result = collect(encode(plan), config, apk, tmp_path / "blocked")
    assert result["status"] == "blocked" and PS not in requests
    assert not (tmp_path / "blocked/trace.json").exists()
    assert (tmp_path / "blocked/preparation.json").exists()


def test_tampering_semantic_replay_and_no_overwrite(tmp_path):
    with setup(tmp_path, max_events=1) as (plan, apk, config, _):
        collect(encode(plan), config, apk, tmp_path / "run", interval=0.1)
        with pytest.raises(FileExistsError):
            collect(encode(plan), config, apk, tmp_path / "run")
    journal_path = tmp_path / "run/observations.json"
    original = journal_path.read_bytes()
    journal_path.write_bytes(original + b" ")
    with pytest.raises(ValueError, match="collection_integrity"):
        verify(tmp_path / "run")
    journal_path.write_bytes(original)
    # Rehashing a forged observation journal cannot override the retained raw snapshot.
    data = json.loads(original)
    data["observations"][0]["event_ids"][0] = "forged"
    raw = encode(data)
    journal_path.write_bytes(raw)
    receipt_path = tmp_path / "run/receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["files"]["observations.json"] = {"sha256": digest(raw), "size_bytes": len(raw)}
    receipt_path.write_bytes(encode(receipt))
    with pytest.raises(ValueError, match="snapshot_trace"):
        verify(tmp_path / "run")


def test_cli_partial_collection_and_offline_verification(tmp_path, capsys):
    with setup(tmp_path, max_events=1) as (plan, apk, config, _):
        plan_path = tmp_path / "plan.json"
        plan_path.write_bytes(encode(plan))
        assert (
            main(
                [
                    "collect",
                    "--plan",
                    str(plan_path),
                    "--profile",
                    str(config),
                    "--apk",
                    str(apk),
                    "--output-dir",
                    str(tmp_path / "run"),
                    "--interval",
                    ".1",
                ]
            )
            == 2
        )
    assert main(["verify", "--directory", str(tmp_path / "run")]) == 0
    assert "process_name_match_not_verified" in capsys.readouterr().out


def test_collector_trace_to_runtime_api_and_combined_report(intake, tmp_path):
    from test_connected_workflow import upload

    from godeep.persistence.models import Sample
    from godeep.workers.runner import run_once

    client, app, _ = intake
    case = client.post("/api/v1/cases", json={"name": "Sampler handoff"}).json()["id"]
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
    raw = client.get(prefix + f"/reports/{report['id']}/download").content
    with app.state.sessions() as session:
        apk = app.state.settings.evidence_root / session.get(Sample, sample["id"]).storage_key
    replies = {}
    with server(faults=replies) as (port, _):
        config = tmp_path / "real-profile.json"
        config.write_text(profile(port).model_dump_json(), encoding="utf-8")
        plan = create_plan(raw, config, duration=1, max_events=1)
        output = f"PID NAME\n123 {plan.package_name}\n".encode()
        replies[PS] = b"OKAY" + packet(1, output) + packet(3, b"\0")
        collect(encode(plan), config, apk, tmp_path / "collected", interval=0.1)
    verify(tmp_path / "collected")
    trace_raw = (tmp_path / "collected/trace.json").read_bytes()
    capture = client.post(
        prefix + "/runtime-captures",
        content=trace_raw,
        headers={"Content-Type": "application/json"},
    )
    assert capture.status_code == 201, capture.text
    assert capture.json()["artifact_sha256"] == digest(trace_raw)
    final = client.post(
        prefix + "/reports",
        json={
            "job_ids": [job["id"]],
            "capture_ids": [capture.json()["id"]],
        },
    )
    assert final.status_code == 201, final.text
    document = client.get(prefix + f"/reports/{final.json()['id']}/download").json()
    event = document["runtime_captures"][0]["data"]["events"][0]
    assert event["action"] == "observed" and event["pid"] == 123


def test_invalid_cli_bundle_and_interval_fail_cleanly(tmp_path, capsys):
    with setup(tmp_path, max_events=1) as (plan, apk, config, requests):
        with pytest.raises(ValueError, match="invalid_sampling_interval"):
            collect(encode(plan), config, apk, tmp_path / "invalid", interval=float("nan"))
        assert requests == []
        collect(encode(plan), config, apk, tmp_path / "run", interval=0.1)
    raw = b"not a zip"
    (tmp_path / "run/bundle.zip").write_bytes(raw)
    receipt_path = tmp_path / "run/receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["files"]["bundle.zip"] = {"sha256": digest(raw), "size_bytes": len(raw)}
    receipt_path.write_bytes(encode(receipt))
    assert main(["verify", "--directory", str(tmp_path / "run")]) == 2
    assert "collection_or_verification_failure" in capsys.readouterr().out
