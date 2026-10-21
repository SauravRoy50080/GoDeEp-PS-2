"""Operator CLI for bounded read-only emulator preflight; no APK execution."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from godeep.sandbox.adb import AdbProbe, ProbeError
from godeep.sandbox.profile import SandboxProfile

VERSION = "1.0.0"


def report_base(status):
    return {
        "schema_version": 1,
        "preflight_version": VERSION,
        "checked_at": datetime.now(UTC).isoformat(),
        "status": status,
        "checks": [],
        "apk_execution": "not_performed",
        "dynamic_capture": "not_performed",
        "isolation": "not_verified",
        "system_image_provenance": "not_verified",
        "limitations": [
            "ADB server and emulator properties are unverified peer assertions",
            "Matching profile values do not authenticate an emulator or establish containment",
            "No network isolation, host-share controls or clean-snapshot restoration is verified",
            "No APK is installed/launched and no runtime trace or malware verdict is generated",
            "Point-in-time checks; future execution needs separate isolation and run controls",
        ],
    }


def preflight(profile):
    result = report_base("blocked")
    result["profile"] = profile.model_dump(mode="json")
    result["adb_server_host"] = "127.0.0.1"
    probe, stage = AdbProbe(profile), "server_version"

    def check(name, value, condition, reason):
        entry = {"name": name, "status": "passed" if condition else "failed"}
        # Store only small printable values, never unbounded server diagnostics.
        if isinstance(value, (bool, int)) or (
            isinstance(value, str) and len(value) <= 100 and value.isprintable()
        ):
            entry["observed"] = value
        if not condition:
            entry["reason"] = reason
        result["checks"].append(entry)
        if not condition:
            raise ProbeError(reason)

    try:
        version = probe.host("version")
        check(
            stage,
            version,
            re.fullmatch(r"[0-9a-fA-F]{4}", version) is not None and int(version, 16) > 0,
            "invalid_server_version",
        )
        stage = "target_state"
        state = probe.host("state")
        check(stage, state, state == "device", "target_not_ready")
        stage = "shell_v2"
        available = "shell_v2" in probe.host("features").split(",")
        check(stage, available, available, "shell_v2_unavailable")
        for name, expected, reason in (
            ("emulator_marker", "1", "emulator_marker_missing"),
            ("avd_name", profile.avd_name, "avd_name_mismatch"),
            ("boot_completed", "1", "boot_incomplete"),
            ("api_level", str(profile.api_level), "api_level_mismatch"),
            ("abi", profile.abi, "abi_mismatch"),
        ):
            stage = name
            observed = probe.property(name)
            check(stage, observed, observed == expected, reason)
    except ProbeError as exc:
        result["reason"] = str(exc)
        if not result["checks"] or result["checks"][-1]["status"] != "failed":
            result["checks"].append({"name": stage, "status": "failed", "reason": str(exc)})
        return result
    result["status"] = "preflight_checks_passed"
    return result


def read_profile(path):
    with path.open("rb") as source:
        raw = source.read(16385)
    if len(raw) > 16384:
        raise ValueError("profile_byte_limit")

    def pairs(items):
        record = {}
        for key, value in items:
            if key in record:
                raise ValueError("duplicate_profile_key")
            record[key] = value
        return record

    def invalid(value):
        raise ValueError("non_finite_profile_value")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int:
        raise ValueError("invalid_profile_schema")
    return SandboxProfile.model_validate(value), hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, help="Private strict JSON emulator profile")
    parser.add_argument(
        "--output", type=Path, help="New UTF-8 report file; existing files are refused"
    )
    args = parser.parse_args(argv)
    if args.profile is None:
        result = report_base("configuration_required")
        result["reason"] = "explicit_emulator_profile_required"
    else:
        try:
            profile, digest = read_profile(args.profile)
        except (OSError, ValueError, TypeError, RecursionError):
            result = report_base("invalid_profile")
            result["reason"] = "profile_unavailable_or_invalid"
        else:
            result = preflight(profile)
            result["profile_sha256"] = digest
    raw = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if args.output is not None:
        try:
            with args.output.open("xb") as target:
                target.write(raw)
        except OSError:
            print(
                "Report output unavailable or already exists; choose a new file.", file=sys.stderr
            )
            return 2
        print("Report SHA-256: " + hashlib.sha256(raw).hexdigest(), file=sys.stderr)
    print(raw.decode("utf-8"), end="")
    return 0 if result["status"] == "preflight_checks_passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
