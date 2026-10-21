"""Offline MISP event-export subset to reproducible, pinned GoDeEp feeds."""

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from godeep.integrations.intelligence.local_feed import Feed, canonical, unique_keys

NAME, VERSION = "godeep.misp-export", "1.0.0"
SOURCE_LIMIT, FEED_LIMIT, RECEIPT_LIMIT = 8388608, 2097152, 4194304
EVENT_LIMIT, ATTRIBUTE_LIMIT, OBJECT_LIMIT = 500, 10000, 2000
FILES = {"source.json", "feed.json", "receipt.json"}


def encode(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False).encode()
        + b"\n"
    )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def invalid(value):
    raise ValueError("non_finite_json")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid)


def read(path, limit):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("artifact_size_limit")
    return raw


def flag(value):
    if type(value) is bool:
        return value
    if (type(value) is int and value in (0, 1)) or (type(value) is str and value in ("0", "1")):
        return str(value) == "1"
    raise ValueError("invalid_boolean_flag")


def stamp(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{1,10}", value) is None:
        raise ValueError("invalid_unix_timestamp")
    return datetime.fromtimestamp(int(value), UTC)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    feed_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    source_name: str = Field(min_length=1, max_length=140)
    source_url: str = Field(min_length=1, max_length=1800)
    published_at: datetime
    valid_hours: int = Field(default=24, ge=1, le=168, strict=True)
    max_attribute_age_days: int = Field(default=30, ge=1, le=365, strict=True)
    classification: Literal["unknown", "benign", "suspicious", "malicious"] = "unknown"
    confidence: Literal["unknown", "low", "medium", "high"] = "unknown"

    @field_validator("published_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_required")
        return value.astimezone(UTC)

    @field_validator("source_url")
    @classmethod
    def base_url(cls, value):
        value = canonical("url", value)
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment:
            raise ValueError("source_base_url_cannot_have_query_or_fragment")
        return value.rstrip("/")


def mapped(kind, value):
    """Composite extraction is syntactic only; no DNS, routing or contact claim."""
    if type(kind) is not str or type(value) is not str or len(value) > 4096:
        raise ValueError("invalid_attribute_value")
    direct = {
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "ip-src": "ip",
        "ip-dst": "ip",
        "sha256": "apk_sha256",
        "x509-fingerprint-sha256": "certificate_sha256",
    }
    if kind in direct:
        selected = [(direct[kind], value)]
    elif kind in {"domain|ip", "ip-src|port", "ip-dst|port", "hostname|port", "filename|sha256"}:
        parts = value.split("|")
        if len(parts) != 2 or not all(parts):
            raise ValueError("invalid_composite_value")
        a, b = parts
        if kind == "domain|ip":
            selected = [("domain", a), ("ip", b)]
        elif kind == "filename|sha256":
            selected = [("apk_sha256", b)]
        else:
            if re.fullmatch(r"[0-9]{1,5}", b) is None or not 1 <= int(b) <= 65535:
                raise ValueError("invalid_composite_port")
            selected = [("domain" if kind == "hostname|port" else "ip", a)]
    else:
        raise ValueError("unsupported_attribute_type")
    result = []
    for target, item in selected:
        if target == "ip":
            if "%" in item or "/" in item:
                raise ValueError("scoped_or_cidr_ip_unsupported")
            ipaddress.ip_address(item)
        result.append((target, canonical(target, item)))
    return result


def convert(raw, policy):
    if len(raw) > SOURCE_LIMIT:
        raise ValueError("source_size_limit")
    data = decode(raw)
    if isinstance(data, dict) and set(data) == {"Event"}:
        wrappers, prefix = [data], ""
    elif (
        isinstance(data, dict) and set(data) == {"response"} and isinstance(data["response"], list)
    ):
        wrappers, prefix = data["response"], "/response"
    else:
        raise ValueError("unsupported_misp_export_shape")
    if not 1 <= len(wrappers) <= EVENT_LIMIT:
        raise ValueError("event_limit_or_empty_export")
    records, provenance, diagnostics, reasons = [], [], [], Counter()
    seen_events, seen_attributes, object_count, scanned = set(), set(), 0, 0
    expires = policy.published_at + timedelta(hours=policy.valid_hours)

    def rejected(pointer, reason):
        reasons[reason] += 1
        diagnostics.append({"snapshot_pointer": pointer, "reason": reason})

    for event_index, wrapper in enumerate(wrappers):
        if (
            not isinstance(wrapper, dict)
            or set(wrapper) != {"Event"}
            or not isinstance(wrapper["Event"], dict)
        ):
            raise ValueError("invalid_event_wrapper")
        event = wrapper["Event"]
        event_id = str(UUID(event["uuid"]))
        if event_id in seen_events:
            raise ValueError("duplicate_event_uuid")
        seen_events.add(event_id)
        event_time = stamp(event["timestamp"])
        if event_time > policy.published_at:
            raise ValueError("event_timestamp_from_future")
        event_reason = (
            "unpublished_event"
            if not flag(event["published"])
            else "deleted_event"
            if flag(event.get("deleted", False))
            else "disabled_event"
            if flag(event.get("disable_correlation", False))
            else None
        )
        root = f"{prefix}/{event_index}/Event" if prefix else "/Event"
        attributes, objects = event.get("Attribute", []), event.get("Object", [])
        if not isinstance(attributes, list) or not isinstance(objects, list):
            raise ValueError("invalid_attribute_or_object_array")
        if len(attributes) > ATTRIBUTE_LIMIT - scanned:
            raise ValueError("attribute_limit")
        rows = [
            (attribute, f"{root}/Attribute/{index}", event_reason)
            for index, attribute in enumerate(attributes)
        ]
        object_count += len(objects)
        if object_count > OBJECT_LIMIT:
            raise ValueError("object_limit")
        for index, obj in enumerate(objects):
            if not isinstance(obj, dict) or not isinstance(obj.get("Attribute", []), list):
                raise ValueError("invalid_object")
            object_reason = event_reason or (
                "deleted_object" if flag(obj.get("deleted", False)) else None
            )
            if len(rows) + len(obj.get("Attribute", [])) > ATTRIBUTE_LIMIT - scanned:
                raise ValueError("attribute_limit")
            rows.extend(
                (attribute, f"{root}/Object/{index}/Attribute/{i}", object_reason)
                for i, attribute in enumerate(obj.get("Attribute", []))
            )
        for attribute, pointer, parent_reason in rows:
            scanned += 1
            if scanned > ATTRIBUTE_LIMIT:
                raise ValueError("attribute_limit")
            if not isinstance(attribute, dict):
                rejected(pointer, "invalid_attribute")
                continue
            try:
                attribute_id = str(UUID(attribute["uuid"]))
            except (ValueError, KeyError, TypeError, AttributeError):
                rejected(pointer, "invalid_attribute_uuid")
                continue
            if attribute_id in seen_attributes:
                raise ValueError("duplicate_attribute_uuid")
            seen_attributes.add(attribute_id)
            try:
                reason = parent_reason or (
                    "deleted_attribute"
                    if flag(attribute.get("deleted", False))
                    else "disabled_attribute"
                    if flag(attribute.get("disable_correlation", False))
                    else "non_detection_attribute"
                    if not flag(attribute["to_ids"])
                    else None
                )
                if reason:
                    rejected(pointer, reason)
                    continue
                modified = stamp(attribute["timestamp"])
                valid_until = min(expires, modified + timedelta(days=policy.max_attribute_age_days))
                if modified > policy.published_at:
                    raise ValueError("attribute_timestamp_from_future")
                if valid_until <= policy.published_at:
                    raise ValueError("stale_attribute")
                values = mapped(attribute["type"], attribute["value"])
            except (ValueError, KeyError, TypeError, OverflowError, OSError) as exc:
                known = {
                    "invalid_boolean_flag",
                    "invalid_unix_timestamp",
                    "invalid_attribute_value",
                    "unsupported_attribute_type",
                    "invalid_composite_value",
                    "invalid_composite_port",
                    "scoped_or_cidr_ip_unsupported",
                    "attribute_timestamp_from_future",
                    "stale_attribute",
                }
                rejected(pointer, str(exc) if str(exc) in known else "invalid_attribute")
                continue
            for kind, value in values:
                if len(records) >= ATTRIBUTE_LIMIT:
                    raise ValueError("indicator_limit")
                record_id = digest(encode([VERSION, event_id, attribute_id, kind, value]))
                records.append(
                    {
                        "id": record_id,
                        "kind": kind,
                        "value": value,
                        "classification": policy.classification,
                        "confidence": policy.confidence,
                        "observed_at": modified.isoformat(),
                        "valid_until": valid_until.isoformat(),
                        "reference": policy.source_url + "/events/view/" + event_id,
                    }
                )
                provenance.append(
                    {
                        "indicator_id": record_id,
                        "event_uuid": event_id,
                        "attribute_uuid": attribute_id,
                        "attribute_type": attribute["type"],
                        "snapshot_pointer": pointer,
                        "timestamp_basis": "misp_attribute_last_modified",
                        "classification_basis": "operator_policy_not_misp_detection_flag",
                    }
                )
    feed = Feed.model_validate(
        {
            "schema_version": 1,
            "feed_id": policy.feed_id,
            "source_name": policy.source_name + " [MISP; labels=operator; times=modified]",
            "source_url": policy.source_url,
            "published_at": policy.published_at,
            "valid_until": expires,
            "indicators": sorted(records, key=lambda item: item["id"]),
        }
    )
    output = encode(feed.model_dump(mode="json"))
    if len(output) > FEED_LIMIT:
        raise ValueError("feed_output_limit")
    receipt = {
        "schema_version": 1,
        "converter": NAME,
        "converter_version": VERSION,
        "policy": policy.model_dump(mode="json"),
        "source": {"sha256": digest(raw), "size_bytes": len(raw)},
        "feed": {"sha256": digest(output), "size_bytes": len(output)},
        "status": "converted" if records else "no_eligible_indicators",
        "coverage": "partial_misp_format_subset",
        "network_requests": 0,
        "summary": {
            "events": len(wrappers),
            "objects": object_count,
            "attributes_scanned": scanned,
            "indicators_emitted": len(records),
            "excluded_attributes": sum(reasons.values()),
        },
        "exclusion_counts": dict(sorted(reasons.items())),
        "provenance": sorted(provenance, key=lambda item: item["indicator_id"]),
        "diagnostics": diagnostics,
        "limitations": [
            "Offline subset; not a full MISP validator or synchronization client",
            "Publication and detection flags are not malware verdicts or independent verification",
            "Labels/confidence are operator assertions; timestamps are modification times",
            "Hash indicators are compared to APK bytes without inferring original file type",
            "Certificate fingerprints are not signature verification or proof of trust",
            "Composite ports/filenames are not matched; domain-IP association is not DNS evidence",
            "Tags, sightings, relationships, proposals and distribution rules are not modeled",
            "Preserve source and receipt; the feed alone omits detailed conversion provenance",
            "Hashes do not authenticate the source or prevent wholesale package rewriting",
        ],
    }
    receipt_raw = encode(receipt)
    if len(receipt_raw) > RECEIPT_LIMIT:
        raise ValueError("receipt_output_limit")
    return output, receipt_raw


def write_package(source, policy, directory):
    raw = read(source, SOURCE_LIMIT)
    feed, receipt = convert(raw, policy)
    directory.mkdir()  # Exclusive; refusal preserves existing evidence.
    for name, content in (("source.json", raw), ("feed.json", feed), ("receipt.json", receipt)):
        with (directory / name).open("xb") as target:
            target.write(content)
    return decode(receipt)


def verify(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("invalid_package_directory")
    members = list(directory.iterdir())
    if {path.name for path in members} != FILES or any(
        path.is_symlink() or not path.is_file() for path in members
    ):
        raise ValueError("unexpected_package_members")
    source = read(directory / "source.json", SOURCE_LIMIT)
    feed = read(directory / "feed.json", FEED_LIMIT)
    receipt_raw = read(directory / "receipt.json", RECEIPT_LIMIT)
    receipt = decode(receipt_raw)
    expected_feed, expected_receipt = convert(source, Policy.model_validate(receipt["policy"]))
    if feed != expected_feed or receipt_raw != expected_receipt:
        raise ValueError("package_replay_mismatch")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    convert_command = commands.add_parser("convert")
    convert_command.add_argument("--source", type=Path, required=True)
    convert_command.add_argument("--output-dir", type=Path, required=True)
    for key in ("feed-id", "source-name", "source-url"):
        convert_command.add_argument("--" + key, required=True)
    convert_command.add_argument("--published-at", default=None)
    convert_command.add_argument("--valid-hours", type=int, default=24)
    convert_command.add_argument("--max-attribute-age-days", type=int, default=30)
    convert_command.add_argument(
        "--classification",
        choices=["unknown", "benign", "suspicious", "malicious"],
        default="unknown",
    )
    convert_command.add_argument(
        "--confidence", choices=["unknown", "low", "medium", "high"], default="unknown"
    )
    check = commands.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            receipt = verify(args.directory)
        else:
            policy = Policy(
                feed_id=args.feed_id,
                source_name=args.source_name,
                source_url=args.source_url,
                published_at=args.published_at or datetime.now(UTC),
                valid_hours=args.valid_hours,
                max_attribute_age_days=args.max_attribute_age_days,
                classification=args.classification,
                confidence=args.confidence,
            )
            receipt = write_package(args.source, policy, args.output_dir)
        print(
            encode(
                {key: receipt[key] for key in ("status", "summary", "feed", "coverage")}
            ).decode(),
            end="",
        )
        return 0 if args.command == "verify" or receipt["status"] == "converted" else 2
    except (
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        OverflowError,
        OSError,
    ):
        print('{"status":"failed","reason":"misp_conversion_or_verification_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
