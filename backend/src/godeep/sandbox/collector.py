"""Passive process snapshots, bounded sampling and verifiable local collection output."""

import argparse
import base64
import io
import math
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

from godeep.sandbox.adb import AdbProbe, ProbeError
from godeep.sandbox.workflow import (
    BUNDLE_LIMIT,
    JSON_LIMIT,
    TRACE_LIMIT,
    Plan,
    bundle,
    decode,
    digest,
    encode,
    prepare,
    read,
    validate_sources,
    verify_bundle,
)
from godeep.schemas.runtime_captures import decode_trace

NAME = "godeep.adb-process-sampler"
VERSION = "1.0.0"
MAX_SNAPSHOTS = 240
MAX_EVENTS = 1000
MAX_RAW = 262144
JOURNAL_LIMIT = 2097152
FILES = {"plan.json", "preparation.json", "trace.json", "observations.json", "bundle.zip"}


def processes(raw, package):
    """Strict PID/NAME table; matching names are candidates, never verified UID ownership."""
    try:
        lines = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
        if not lines or lines[0].split() != ["PID", "NAME"] or len(lines) > 4097:
            raise ValueError("unsupported_ps_format")
        seen, selected = set(), []
        for line in lines[1:]:
            fields = line.split(None, 1)
            if len(fields) != 2 or re.fullmatch(r"[0-9]{1,10}", fields[0]) is None:
                raise ValueError("invalid_ps_row")
            pid, name = int(fields[0]), fields[1]
            if not 1 <= pid <= 2147483647 or pid in seen:
                raise ValueError("invalid_or_duplicate_pid")
            seen.add(pid)
            if name == package or name.startswith(package + ":"):
                if len(name) > 200 or not name.isprintable():
                    raise ValueError("unsupported_process_name")
                selected.append((pid, name))
        return sorted(selected)
    except UnicodeError as exc:
        raise ValueError("invalid_ps_encoding") from exc


def sample(plan_raw, preparation_raw, interval=1.0):
    if not math.isfinite(interval) or not 0.1 <= interval <= 30:
        raise ValueError("invalid_sampling_interval")
    plan = Plan.model_validate(decode(plan_raw))
    if "process" not in plan.requested_streams:
        raise ValueError("process_stream_not_requested")
    started = datetime.now(UTC)
    trace = {
        "schema_version": 1,
        "input_sha256": plan.input_sha256,
        "source_run_id": str(plan.run_id),
        "collector": {"name": NAME, "version": VERSION},
        "environment": "emulator",
        "package_name": plan.package_name,
        "started_at": started.isoformat(),
        "ended_at": started.isoformat(),
        "collection_status": "partial",
        "coverage": {
            "process": "partial",
            "filesystem": "not_collected",
            "network": "not_collected",
            "sensitive_access": "not_collected",
        },
        "events": [],
    }
    validate_sources(plan_raw, preparation_raw, encode(trace))  # Gate before any process query.
    anchor = time.monotonic()
    deadline = anchor + plan.duration_seconds
    observations, raw_total, reason = [], 0, None
    event_cap = min(plan.max_events, MAX_EVENTS)

    def timestamp():
        return (
            started + timedelta(seconds=min(time.monotonic() - anchor, plan.duration_seconds))
        ).isoformat()

    while time.monotonic() < deadline:
        if len(observations) >= MAX_SNAPSHOTS:
            reason = "snapshot_limit"
            break
        if len(trace["events"]) >= event_cap:
            reason = "event_limit"
            break
        probe = AdbProbe(plan.profile)
        probe.deadline = min(probe.deadline, deadline)
        try:
            raw = probe.process_snapshot()
        except ProbeError as exc:
            observations.append(
                {
                    "timestamp": timestamp(),
                    "status": "probe_failed",
                    "reason": str(exc),
                    "event_ids": [],
                }
            )
            reason = "probe_failed"
            break
        if raw_total + len(raw) > MAX_RAW:
            reason = "raw_output_limit"
            break
        raw_total += len(raw)
        record = {
            "timestamp": timestamp(),
            "status": "parsed",
            "raw_sha256": digest(raw),
            "raw_base64": base64.b64encode(raw).decode("ascii"),
            "event_ids": [],
        }
        observations.append(record)
        try:
            selected = processes(raw, plan.package_name)
        except ValueError:
            record["status"] = "invalid_snapshot"
            reason = "unsupported_ps_output"
            break
        record["matching_rows"] = len(selected)
        for pid, name in selected[: event_cap - len(trace["events"])]:
            event_id = str(uuid4())
            record["event_ids"].append(event_id)
            trace["events"].append(
                {
                    "event_id": event_id,
                    "timestamp": record["timestamp"],
                    "pid": pid,
                    "kind": "process",
                    "action": "observed",
                    "name": name,
                }
            )
        if len(trace["events"]) >= event_cap:
            reason = "event_limit"
            break
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
    trace["ended_at"] = timestamp()
    parsed_count = sum(record["status"] == "parsed" for record in observations)
    if not observations and reason is None:
        reason = "no_samples"
    trace["coverage"]["process"] = "partial" if parsed_count else "not_collected"
    trace["collection_status"] = (
        "failed" if reason and not parsed_count else "partial" if reason else "completed"
    )
    journal = {
        "schema_version": 1,
        "collector_version": VERSION,
        "run_id": str(plan.run_id),
        "plan_sha256": digest(plan_raw),
        "preparation_sha256": digest(preparation_raw),
        "timestamp_basis": "host_utc_anchor_plus_monotonic_elapsed_capped_to_planned_window",
        "actual_elapsed_seconds": time.monotonic() - anchor,
        "interval_seconds": interval,
        "termination_reason": reason,
        "observations": observations,
        "attribution": "process_name_match_not_verified",
        "absence_inference": "not_performed",
    }
    trace_raw, journal_raw = encode(trace), encode(journal)
    if len(journal_raw) > JOURNAL_LIMIT:
        raise ValueError("journal_limit")
    validate_sources(plan_raw, preparation_raw, trace_raw)
    return trace_raw, journal_raw


def write_new(path, raw):
    with path.open("xb") as target:
        target.write(raw)


def collect(plan_raw, profile_path, apk_path, directory, interval=1.0):
    if not math.isfinite(interval) or not 0.1 <= interval <= 30:
        raise ValueError("invalid_sampling_interval")
    plan = Plan.model_validate(decode(plan_raw))
    if "process" not in plan.requested_streams:
        raise ValueError("process_stream_not_requested")
    directory = Path(directory)
    directory.mkdir()  # Exclusive new session directory; never replace investigator files.
    preparation = prepare(plan_raw, profile_path, apk_path)
    sources = {"plan.json": plan_raw, "preparation.json": encode(preparation)}
    for name, raw in sources.items():
        write_new(directory / name, raw)
    if preparation.status == "blocked":
        write_new(
            directory / "blocked.json",
            encode(
                {
                    "schema_version": 1,
                    "status": "blocked",
                    "reason": preparation.preflight.get("reason"),
                    "apk_execution": "not_performed",
                }
            ),
        )
        return {"status": "blocked", "apk_execution": "not_performed"}
    trace_raw, journal_raw = sample(plan_raw, sources["preparation.json"], interval)
    sources.update(
        {
            "trace.json": trace_raw,
            "observations.json": journal_raw,
            "bundle.zip": bundle(plan_raw, sources["preparation.json"], trace_raw),
        }
    )
    for name in ("trace.json", "observations.json", "bundle.zip"):
        write_new(directory / name, sources[name])
    trace = decode_trace(trace_raw)
    receipt = {
        "schema_version": 1,
        "collector": NAME,
        "collector_version": VERSION,
        "run_id": trace.source_run_id,
        "collection_status": trace.collection_status,
        "attribution": "process_name_match_not_verified",
        "isolation": "not_verified",
        "apk_execution": "not_performed",
        "event_count": len(trace.events),
        "files": {
            name: {"sha256": digest(raw), "size_bytes": len(raw)} for name, raw in sources.items()
        },
    }
    write_new(
        directory / "receipt.json", encode(receipt)
    )  # Seal only after every artifact is written.
    return receipt


def verify(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid_collection_directory")
    names = set()
    for item in directory.iterdir():
        names.add(item.name)
        if len(names) > 6 or item.is_symlink() or not item.is_file():
            raise ValueError("collection_members_invalid")
    if names != FILES | {"receipt.json"}:
        raise ValueError("collection_members_invalid")
    sources = {
        name: read(
            directory / name,
            BUNDLE_LIMIT
            if name == "bundle.zip"
            else JOURNAL_LIMIT
            if name == "observations.json"
            else TRACE_LIMIT
            if name == "trace.json"
            else JSON_LIMIT,
        )
        for name in FILES
    }
    receipt = decode(read(directory / "receipt.json", JSON_LIMIT))
    expected_files = {
        name: {"sha256": digest(raw), "size_bytes": len(raw)} for name, raw in sources.items()
    }
    if receipt.get("files") != expected_files:
        raise ValueError("collection_integrity_mismatch")
    manifest, trace_raw = verify_bundle(sources["bundle.zip"])
    if trace_raw != sources["trace.json"]:
        raise ValueError("trace_bundle_mismatch")
    with ZipFile(io.BytesIO(sources["bundle.zip"])) as archive:
        for name in ("plan.json", "preparation.json"):
            if archive.read(name) != sources[name]:
                raise ValueError("bundle_source_mismatch")
    plan, _, trace = validate_sources(sources["plan.json"], sources["preparation.json"], trace_raw)
    journal = decode(sources["observations.json"])
    if (
        journal.get("plan_sha256") != digest(sources["plan.json"])
        or journal.get("preparation_sha256") != digest(sources["preparation.json"])
        or journal.get("run_id") != str(plan.run_id)
        or trace.collector.name != NAME
        or trace.collector.version != VERSION
    ):
        raise ValueError("collection_identity_mismatch")
    expected_coverage = {
        "process": "partial"
        if any(record.get("status") == "parsed" for record in journal["observations"])
        else "not_collected",
        "filesystem": "not_collected",
        "network": "not_collected",
        "sensitive_access": "not_collected",
    }
    reason = journal.get("termination_reason")
    if reason not in (
        None,
        "snapshot_limit",
        "event_limit",
        "raw_output_limit",
        "probe_failed",
        "unsupported_ps_output",
        "no_samples",
    ):
        raise ValueError("invalid_termination_reason")
    expected_status = (
        "failed"
        if reason and expected_coverage["process"] == "not_collected"
        else "partial"
        if reason
        else "completed"
    )
    if (
        trace.coverage.model_dump() != expected_coverage
        or trace.collection_status != expected_status
        or journal.get("collector_version") != VERSION
        or journal.get("attribution") != "process_name_match_not_verified"
        or journal.get("absence_inference") != "not_performed"
    ):
        raise ValueError("collection_coverage_mismatch")
    elapsed, interval = journal.get("actual_elapsed_seconds"), journal.get("interval_seconds")
    if (
        type(elapsed) not in (int, float)
        or not math.isfinite(elapsed)
        or elapsed < 0
        or type(interval) not in (int, float)
        or not math.isfinite(interval)
        or not 0.1 <= interval <= 30
        or journal.get("timestamp_basis")
        != "host_utc_anchor_plus_monotonic_elapsed_capped_to_planned_window"
    ):
        raise ValueError("collection_clock_metadata_mismatch")
    replay, total_raw, previous = [], 0, trace.started_at
    records = journal["observations"]
    if len(records) > MAX_SNAPSHOTS:
        raise ValueError("snapshot_limit")
    for record in records:
        stamp = datetime.fromisoformat(record["timestamp"])
        if stamp.utcoffset() is None or not previous <= stamp <= trace.ended_at:
            raise ValueError("snapshot_time_mismatch")
        previous = stamp
        if record["status"] == "probe_failed":
            if record is not records[-1] or reason != "probe_failed":
                raise ValueError("probe_failure_order")
            if record["event_ids"]:
                raise ValueError("failed_probe_events")
            continue
        encoded = record["raw_base64"]
        if len(encoded) > ((plan.profile.max_output_bytes + 2) // 3) * 4:
            raise ValueError("snapshot_output_limit")
        raw = base64.b64decode(encoded, validate=True)
        total_raw += len(raw)
        if (
            digest(raw) != record["raw_sha256"]
            or len(raw) > plan.profile.max_output_bytes
            or total_raw > MAX_RAW
        ):
            raise ValueError("snapshot_integrity_mismatch")
        try:
            selected = processes(raw, plan.package_name)
        except ValueError:
            if (
                record["status"] != "invalid_snapshot"
                or record["event_ids"]
                or record is not records[-1]
                or reason != "unsupported_ps_output"
            ):
                raise ValueError("snapshot_parse_mismatch") from None
            continue
        if record["status"] != "parsed" or record["matching_rows"] != len(selected):
            raise ValueError("snapshot_parse_mismatch")
        ids = record["event_ids"]
        if len(ids) != min(len(selected), min(plan.max_events, MAX_EVENTS) - len(replay)):
            raise ValueError("snapshot_event_count")
        replay.extend((event_id, pid, name, stamp) for event_id, (pid, name) in zip(ids, selected))
    actual = [
        (str(event.event_id), event.pid, event.name, event.timestamp)
        for event in trace.events
        if event.kind == "process" and event.action == "observed"
    ]
    if replay != actual or len(actual) != len(trace.events):
        raise ValueError("snapshot_trace_mismatch")
    expected = {
        "schema_version": 1,
        "collector": NAME,
        "collector_version": VERSION,
        "run_id": str(plan.run_id),
        "collection_status": trace.collection_status,
        "attribution": "process_name_match_not_verified",
        "isolation": "not_verified",
        "apk_execution": "not_performed",
        "event_count": len(trace.events),
        "files": expected_files,
    }
    if receipt != expected or manifest["input_sha256"] != plan.input_sha256:
        raise ValueError("collection_receipt_mismatch")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("collect")
    for key in ("plan", "profile", "apk", "output-dir"):
        capture.add_argument("--" + key, type=Path, required=True)
    capture.add_argument("--interval", type=float, default=1)
    check = commands.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = (
            collect(
                read(args.plan, JSON_LIMIT), args.profile, args.apk, args.output_dir, args.interval
            )
            if args.command == "collect"
            else verify(args.directory)
        )
        print(encode(result).decode("utf-8"), end="")
        return (
            0 if args.command == "verify" or result.get("collection_status") == "completed" else 2
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, BadZipFile):
        print('{"status":"failed","reason":"collection_or_verification_failure"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
