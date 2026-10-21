"""Operator run plans, preflight preparations and exact-byte collector bundles."""

import argparse
import hashlib
import io
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator

from godeep.sandbox.doctor import preflight, read_profile
from godeep.sandbox.profile import SandboxProfile
from godeep.schemas.runtime_captures import decode_trace

VERSION = "1.0.0"
JSON_LIMIT = 65536
TRACE_LIMIT = 2097152
BUNDLE_LIMIT = 3145728
SUPPORTED = {("static_review", "1.0.1"), ("threat_review", "1.0.0")}
CHECKS = [
    "server_version",
    "target_state",
    "shell_v2",
    "emulator_marker",
    "avd_name",
    "boot_completed",
    "api_level",
    "abi",
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def read(path, limit):
    with Path(path).open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("source_byte_limit")
    return raw


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("non_finite_json")

    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(result, dict) or type(result.get("schema_version")) is not int:
        raise ValueError("invalid_schema")
    return result


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    workflow_version: Literal["1.0.0"] = VERSION


class Plan(Record):
    run_id: UUID
    created_at: datetime
    report_id: UUID
    case_id: UUID
    sample_id: UUID
    source_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_size_bytes: int = Field(ge=1, le=209715200, strict=True)
    package_name: str = Field(
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$", max_length=255
    )
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile: SandboxProfile
    duration_seconds: int = Field(default=60, ge=1, le=300, strict=True)
    max_events: int = Field(default=2000, ge=1, le=2000, strict=True)
    requested_streams: list[Literal["process", "filesystem", "network", "sensitive_access"]] = (
        Field(
            default_factory=lambda: ["process", "filesystem", "network", "sensitive_access"],
            min_length=1,
            max_length=4,
        )
    )
    execution_authorization: Literal["not_granted"] = "not_granted"

    @field_validator("created_at")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("aware_time_required")
        return value

    @field_validator("requested_streams")
    @classmethod
    def distinct(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("duplicate_stream")
        return value


class Preparation(Record):
    run_id: UUID
    plan_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    prepared_at: datetime
    status: Literal["blocked", "preflight_passed_execution_not_authorized"]
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    preflight: dict
    execution_authorization: Literal["not_granted"] = "not_granted"

    @field_validator("prepared_at")
    @classmethod
    def aware(cls, value):
        return Plan.aware(value)


def create_plan(report_raw, profile_path, duration=60, max_events=2000):
    if len(report_raw) > 10485760:
        raise ValueError("report_byte_limit")
    report = decode(report_raw)
    if (
        report["schema_version"] not in (1, 2)
        or report["report_type"] != "investigation_analysis_snapshot"
    ):
        raise ValueError("unsupported_report")
    if not isinstance(report["analyses"], list) or not 1 <= len(report["analyses"]) <= 20:
        raise ValueError("report_source_count")
    packages = set()
    for source in report["analyses"]:
        pair = source["adapter"], source["adapter_version"]
        if pair not in SUPPORTED:
            continue
        data = source["data"]
        if (data["adapter"], data["adapter_version"]) != pair or data["input_sha256"] != report[
            "sample"
        ]["sha256"]:
            raise ValueError("source_identity_mismatch")
        if data.get("manifest"):
            packages.add(data["manifest"]["identity"]["package_name"])
    if len(packages) != 1:
        raise ValueError("unique_static_package_required")
    profile, profile_hash = read_profile(profile_path)
    return Plan(
        schema_version=1,
        run_id=uuid4(),
        created_at=datetime.now(UTC),
        report_id=report["report_id"],
        case_id=report["case"]["id"],
        sample_id=report["sample"]["id"],
        source_report_sha256=digest(report_raw),
        input_sha256=report["sample"]["sha256"],
        input_size_bytes=report["sample"]["size_bytes"],
        package_name=packages.pop(),
        profile_sha256=profile_hash,
        profile=profile,
        duration_seconds=duration,
        max_events=max_events,
    )


def prepare(plan_raw, profile_path, apk_path):
    if len(plan_raw) > JSON_LIMIT:
        raise ValueError("plan_byte_limit")
    plan = Plan.model_validate(decode(plan_raw))
    now = datetime.now(UTC)
    if not timedelta(0) <= now - plan.created_at <= timedelta(days=1):
        raise ValueError("plan_expired_or_future")
    profile, profile_hash = read_profile(profile_path)
    if profile_hash != plan.profile_sha256 or profile != plan.profile:
        raise ValueError("profile_mismatch")
    measured, size = hashlib.sha256(), 0
    with Path(apk_path).open("rb") as source:
        while chunk := source.read(1048576):
            size += len(chunk)
            if size > plan.input_size_bytes:
                raise ValueError("input_size_mismatch")
            measured.update(chunk)
    if measured.hexdigest() != plan.input_sha256 or size != plan.input_size_bytes:
        raise ValueError("input_integrity_mismatch")
    result = preflight(profile)
    return Preparation(
        schema_version=1,
        run_id=plan.run_id,
        plan_sha256=digest(plan_raw),
        prepared_at=datetime.now(UTC),
        input_sha256=plan.input_sha256,
        profile_sha256=profile_hash,
        preflight=result,
        status="preflight_passed_execution_not_authorized"
        if result["status"] == "preflight_checks_passed"
        else "blocked",
    )


def validate_sources(plan_raw, preparation_raw, trace_raw):
    if (
        len(plan_raw) > JSON_LIMIT
        or len(preparation_raw) > JSON_LIMIT
        or len(trace_raw) > TRACE_LIMIT
    ):
        raise ValueError("source_byte_limit")
    plan = Plan.model_validate(decode(plan_raw))
    preparation = Preparation.model_validate(decode(preparation_raw))
    trace = decode_trace(trace_raw)
    if (
        preparation.plan_sha256 != digest(plan_raw)
        or preparation.run_id != plan.run_id
        or preparation.input_sha256 != plan.input_sha256
        or preparation.profile_sha256 != plan.profile_sha256
    ):
        raise ValueError("preparation_identity_mismatch")
    checks = preparation.preflight.get("checks", [])
    if (
        preparation.status != "preflight_passed_execution_not_authorized"
        or preparation.preflight.get("status") != "preflight_checks_passed"
        or [check.get("name") for check in checks] != CHECKS
        or any(check.get("status") != "passed" for check in checks)
        or preparation.preflight.get("profile") != plan.profile.model_dump(mode="json")
        or preparation.preflight.get("isolation") != "not_verified"
    ):
        raise ValueError("passing_preparation_required")
    observed = {check["name"]: check.get("observed") for check in checks}
    version = observed.get("server_version")
    if (
        not isinstance(version, str)
        or re.fullmatch(r"[0-9a-fA-F]{4}", version) is None
        or int(version, 16) == 0
        or observed.get("target_state") != "device"
        or observed.get("shell_v2") is not True
        or observed.get("emulator_marker") != "1"
        or observed.get("avd_name") != plan.profile.avd_name
        or observed.get("boot_completed") != "1"
        or observed.get("api_level") != str(plan.profile.api_level)
        or observed.get("abi") != plan.profile.abi
        or preparation.preflight.get("adb_server_host") != "127.0.0.1"
        or preparation.preflight.get("apk_execution") != "not_performed"
        or preparation.preflight.get("dynamic_capture") != "not_performed"
    ):
        raise ValueError("preflight_observation_mismatch")
    checked = datetime.fromisoformat(preparation.preflight["checked_at"])
    if (
        checked.utcoffset() is None
        or checked < plan.created_at
        or not timedelta(0)
        <= preparation.prepared_at - checked
        <= timedelta(seconds=plan.profile.total_timeout_seconds + 5)
    ):
        raise ValueError("preflight_time_mismatch")
    if not timedelta(0) <= preparation.prepared_at - plan.created_at <= timedelta(days=1):
        raise ValueError("preparation_time_mismatch")
    if (
        trace.input_sha256 != plan.input_sha256
        or trace.package_name != plan.package_name
        or trace.source_run_id != str(plan.run_id)
        or trace.environment != "emulator"
    ):
        raise ValueError("trace_identity_mismatch")
    if not timedelta(0) <= trace.started_at - preparation.prepared_at <= timedelta(minutes=10):
        raise ValueError("preflight_freshness_mismatch")
    if (
        trace.ended_at - trace.started_at > timedelta(seconds=plan.duration_seconds)
        or len(trace.events) > plan.max_events
    ):
        raise ValueError("collection_bounds_exceeded")
    for name, coverage in trace.coverage.model_dump().items():
        if name not in plan.requested_streams and coverage != "not_collected":
            raise ValueError("unrequested_stream")
    return plan, preparation, trace


def bundle(plan_raw, preparation_raw, trace_raw):
    plan, _, trace = validate_sources(plan_raw, preparation_raw, trace_raw)
    if trace.ended_at > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("future_trace")
    sources = {"plan.json": plan_raw, "preparation.json": preparation_raw, "trace.json": trace_raw}
    manifest = {
        "schema_version": 1,
        "workflow_version": VERSION,
        "run_id": str(plan.run_id),
        "case_id": str(plan.case_id),
        "sample_id": str(plan.sample_id),
        "input_sha256": plan.input_sha256,
        "collection_status": trace.collection_status,
        "coverage": trace.coverage.model_dump(),
        "attribution": "collector_asserted_not_verified",
        "isolation": "not_verified",
        "apk_execution_verification": "not_performed",
        "files": {
            name: {"sha256": digest(raw), "size_bytes": len(raw)} for name, raw in sources.items()
        },
    }
    sources["manifest.json"] = encode(manifest)
    output = io.BytesIO()
    with ZipFile(output, "w", compression=ZIP_STORED) as archive:
        for name in sorted(sources):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, sources[name])
    return output.getvalue()


def verify_bundle(raw):
    if len(raw) > BUNDLE_LIMIT:
        raise ValueError("bundle_byte_limit")
    names = {"manifest.json", "plan.json", "preparation.json", "trace.json"}
    with ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        if len(members) != 4 or {member.filename for member in members} != names:
            raise ValueError("bundle_members_invalid")
        sources = {}
        for member in members:
            limit = TRACE_LIMIT if member.filename == "trace.json" else JSON_LIMIT
            if (
                member.file_size > limit
                or member.compress_type != ZIP_STORED
                or member.flag_bits & 1
            ):
                raise ValueError("bundle_member_bounds")
            with archive.open(member) as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("bundle_member_bounds")
            sources[member.filename] = data
    manifest = decode(sources.pop("manifest.json"))
    actual = {
        name: {"sha256": digest(data), "size_bytes": len(data)} for name, data in sources.items()
    }
    if manifest.get("files") != actual:
        raise ValueError("bundle_integrity_mismatch")
    expected = bundle(sources["plan.json"], sources["preparation.json"], sources["trace.json"])
    with ZipFile(io.BytesIO(expected)) as archive:
        if decode(archive.read("manifest.json")) != manifest:
            raise ValueError("bundle_metadata_mismatch")
    if raw != expected:
        raise ValueError("noncanonical_bundle")
    return manifest, sources["trace.json"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan")
    plan_cmd.add_argument("--report", type=Path, required=True)
    plan_cmd.add_argument("--profile", type=Path, required=True)
    plan_cmd.add_argument("--duration", type=int, default=60)
    plan_cmd.add_argument("--max-events", type=int, default=2000)
    prep_cmd = commands.add_parser("prepare")
    prep_cmd.add_argument("--plan", type=Path, required=True)
    prep_cmd.add_argument("--profile", type=Path, required=True)
    prep_cmd.add_argument("--apk", type=Path, required=True)
    bundle_cmd = commands.add_parser("bundle")
    for name in ("plan", "preparation", "trace"):
        bundle_cmd.add_argument("--" + name, type=Path, required=True)
    verify_cmd = commands.add_parser("verify")
    verify_cmd.add_argument("--bundle", type=Path, required=True)
    verify_cmd.add_argument("--trace-output", type=Path)
    for command in (plan_cmd, prep_cmd, bundle_cmd):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = create_plan(
                read(args.report, 10485760), args.profile, args.duration, args.max_events
            )
            raw = encode(result)
        elif args.command == "prepare":
            result = prepare(read(args.plan, JSON_LIMIT), args.profile, args.apk)
            raw = encode(result)
        elif args.command == "bundle":
            raw = bundle(
                read(args.plan, JSON_LIMIT),
                read(args.preparation, JSON_LIMIT),
                read(args.trace, TRACE_LIMIT),
            )
        else:
            bundle_raw = read(args.bundle, BUNDLE_LIMIT)
            manifest, trace_raw = verify_bundle(bundle_raw)
            if args.trace_output is not None:
                with args.trace_output.open("xb") as output:
                    output.write(trace_raw)
            print(
                json.dumps(
                    {
                        "status": "verified_in_bundle_scope",
                        "artifact_sha256": digest(bundle_raw),
                        "manifest": manifest,
                    },
                    sort_keys=True,
                )
            )
            return 0
        with args.output.open("xb") as output:
            output.write(raw)
        print(
            json.dumps(
                {"artifact_sha256": digest(raw), "size_bytes": len(raw), "command": args.command},
                sort_keys=True,
            )
        )
        return 2 if args.command == "prepare" and result.status == "blocked" else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, BadZipFile):
        print(json.dumps({"status": "failed", "reason": "workflow_validation_or_output_failure"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
