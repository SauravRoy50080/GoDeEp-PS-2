"""Bounded, read-only runtime inventories derived from verified report snapshots."""

import hashlib
import json
import re
from datetime import UTC
from html import escape
from uuid import UUID

from fastapi import HTTPException

from godeep.schemas.runtime_captures import RuntimeTrace
from godeep.services.report_html import STYLE
from godeep.services.reports import download_report

VERSION = "1.0.0"
KINDS = ("process", "filesystem", "network", "sensitive_access")
LIMITATIONS = [
    "Selected recorded observations only; missing items do not establish absence",
    "Attribution, package ownership, clocks and isolation are collector assertions, not verified",
    "Repeated observations and overlapping captures are counts, not independent confirmation",
    "Process action observed is presence in a snapshot, not a start or stop",
    "Names and PIDs do not establish process continuity, UID ownership or APK execution",
    "File paths and operations are exact collector strings; no resolution or content inspection",
    "Network records do not prove successful contact, data transfer, exfiltration or maliciousness",
    "Sensitive-resource operations are collector strings, not independent access verification",
    "Activity buckets use elapsed collector time per capture; cross-capture clocks are not aligned",
    "Pointers reference normalized report JSON; artifact hashes identify original trace bytes",
    "Original and source artifacts were checked at report creation and are not re-read here",
    "Derived read-only view; no report mutation, risk score, malware verdict or model inference",
]


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate snapshot key")
        result[key] = value
    return result


def load(factory, settings, case_id, sample_id, report_id, user_id):
    """Authorization and report hash checks precede snapshot parsing and selection."""
    report, raw = download_report(factory, settings, case_id, sample_id, report_id, user_id)
    try:
        document = json.loads(raw, object_pairs_hook=_pairs)
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 2
            or report.schema_version != 2
            or document["report_type"] != "investigation_analysis_snapshot"
            or document["report_id"] != report.id
            or document["case"]["id"] != case_id
            or document["sample"]["id"] != sample_id
            or document["sample"]["sha256"] != report.input_sha256
            or not isinstance(document["analyses"], list)
            or not isinstance(document["runtime_captures"], list)
            or not 1 <= len(document["analyses"]) + len(document["runtime_captures"]) <= 20
        ):
            raise ValueError("Runtime snapshot identity mismatch")
        sources = validate(document)
        if not sources:
            raise ValueError("Runtime sources required")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise HTTPException(409, "Report snapshot is not valid for runtime review") from exc
    return document, sources, report.artifact_sha256


def validate(document):
    sources, ids = [], set()
    for index, source in enumerate(document["runtime_captures"]):
        capture_id = source["capture_id"]
        if str(UUID(capture_id)) != capture_id or capture_id in ids:
            raise ValueError("Invalid or duplicate capture ID")
        ids.add(capture_id)
        if not re.fullmatch(r"[a-f0-9]{64}", source["artifact_sha256"]):
            raise ValueError("Invalid trace hash")
        if type(source["data"]["schema_version"]) is not int:
            raise ValueError("Invalid trace schema version")
        trace = RuntimeTrace.model_validate(source["data"])
        if (
            trace.input_sha256 != document["sample"]["sha256"]
            or trace.source_run_id != source["source_run_id"]
            or source["representation"] != "validated_normalized_trace_v1"
            or source["attribution"] != "collector_asserted_not_verified"
            or source["isolation"] != "not_verified"
        ):
            raise ValueError("Capture identity mismatch")
        sources.append((index, source, trace))
    return sources


def descriptor(entry):
    index, source, trace = entry
    return {
        "capture_id": source["capture_id"],
        "artifact_sha256": source["artifact_sha256"],
        "source_run_id": trace.source_run_id,
        "collector": trace.collector.model_dump(),
        "environment": trace.environment,
        "package_name": trace.package_name,
        "started_at": trace.started_at.isoformat(),
        "ended_at": trace.ended_at.isoformat(),
        "collection_status": trace.collection_status,
        "coverage": trace.coverage.model_dump(),
        "attribution": "collector_asserted_not_verified",
        "isolation": "not_verified",
        "snapshot_pointer": f"/runtime_captures/{index}",
    }


def dimensions(event):
    if event.kind == "process":
        return {"name": event.name, "action": event.action}
    if event.kind == "filesystem":
        return {
            "path": event.path,
            "operation": event.operation,
            "content_sha256": event.content_sha256,
        }
    if event.kind == "network":
        return {
            "transport": event.transport,
            "destination_ip": str(event.destination_ip),
            "destination_port": event.destination_port,
        }
    return {"resource": event.resource, "operation": event.operation}


def key_of(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def inventory(sources, section, settings, bucket_seconds):
    """Exact event groups or sparse per-capture elapsed buckets; never merge PIDs."""
    groups, scanned = {}, 0
    for index, source, trace in sources:
        capture_id = source["capture_id"]
        for event_index, event in enumerate(trace.events):
            scanned += 1
            if scanned > settings.max_runtime_review_events:
                raise HTTPException(413, "Runtime review event budget exceeded")
            if section != "activity" and event.kind != section:
                continue
            if section == "activity":
                elapsed = (event.timestamp - trace.started_at).total_seconds()
                bucket = int(elapsed // bucket_seconds)
                identity = {
                    "capture_id": capture_id,
                    "elapsed_start_seconds": bucket * bucket_seconds,
                    "elapsed_end_exclusive_seconds": (bucket + 1) * bucket_seconds,
                }
            else:
                identity = dimensions(event)
            key = key_of(identity)
            if key not in groups:
                if len(groups) >= settings.max_runtime_review_groups:
                    raise HTTPException(413, "Runtime review group budget exceeded")
                groups[key] = {
                    "identity": identity,
                    "count": 0,
                    "capture_counts": {},
                    "event_kind_counts": dict.fromkeys(KINDS, 0),
                    "first_observed_at": None,
                    "last_observed_at": None,
                    "evidence": [],
                }
            group = groups[key]
            stamp = event.timestamp.astimezone(UTC).isoformat()
            group["count"] += 1
            group["capture_counts"][capture_id] = group["capture_counts"].get(capture_id, 0) + 1
            group["event_kind_counts"][event.kind] += 1
            # Extrema are time labels only; no cross-capture causal ordering is claimed.
            group["first_observed_at"] = min(group["first_observed_at"] or stamp, stamp)
            group["last_observed_at"] = max(group["last_observed_at"] or stamp, stamp)
            if len(group["evidence"]) < settings.max_runtime_review_evidence:
                group["evidence"].append(
                    {
                        "capture_id": capture_id,
                        "artifact_sha256": source["artifact_sha256"],
                        "event_id": str(event.event_id),
                        "pid": event.pid,
                        "timestamp": event.timestamp.isoformat(),
                        "kind": event.kind,
                        "snapshot_pointer": f"/runtime_captures/{index}/data/events/{event_index}",
                    }
                )
    ordered = list(groups.values())
    if section == "activity":
        ordered.sort(
            key=lambda item: (
                item["identity"]["capture_id"],
                item["identity"]["elapsed_start_seconds"],
            )
        )
    else:
        ordered.sort(key=lambda item: key_of(item["identity"]))
    for group in ordered:
        group["evidence_limited"] = len(group["evidence"]) < group["count"]
    return ordered, scanned


def derive(
    document,
    sources,
    settings,
    *,
    section,
    limit=100,
    offset=0,
    bucket_seconds=10,
    capture_id=None,
    left=None,
    right=None,
):
    comparing = left is not None or right is not None
    if section not in (*KINDS, "activity") or not 1 <= bucket_seconds <= 3600:
        raise HTTPException(422, "Invalid runtime review section or bucket interval")
    if not 1 <= limit <= 200 or not 0 <= offset <= 40000:
        raise HTTPException(422, "Invalid runtime review pagination")
    if comparing and (
        not left or not right or left == right or capture_id or section == "activity"
    ):
        raise HTTPException(
            422, "Comparison requires two distinct captures and an inventory section"
        )
    wanted = {left, right} if comparing else {capture_id} if capture_id else None
    selected = [entry for entry in sources if wanted is None or entry[1]["capture_id"] in wanted]
    if wanted and {entry[1]["capture_id"] for entry in selected} != wanted:
        raise HTTPException(404, "Capture not selected in this report")
    items, scanned = inventory(selected, section, settings, bucket_seconds)
    summary = {"both_selected_captures": 0, "left_selection_only": 0, "right_selection_only": 0}
    if comparing:
        for item in items:
            counts = item["capture_counts"]
            a, b = counts.get(left, 0), counts.get(right, 0)
            relation = (
                "both_selected_captures"
                if a and b
                else "left_selection_only"
                if a
                else "right_selection_only"
            )
            item.update(relationship=relation, left_count=a, right_count=b, count_delta=b - a)
            summary[relation] += 1
    return {
        "schema_version": 1,
        "review_version": VERSION,
        "view": "runtime_capture_comparison" if comparing else "runtime_review",
        "report_id": document["report_id"],
        "case_id": document["case"]["id"],
        "sample_id": document["sample"]["id"],
        "input_sha256": document["sample"]["sha256"],
        "section": section,
        "selection": {
            "capture_ids": [entry[1]["capture_id"] for entry in selected],
            "left_capture_id": left,
            "right_capture_id": right,
        },
        "sources": [descriptor(entry) for entry in selected],
        "events_scanned": scanned,
        "matching_event_count": sum(item["count"] for item in items),
        "total": len(items),
        "items": items[offset : offset + limit],
        "limit": limit,
        "offset": offset,
        "evidence_limited": any(item["evidence_limited"] for item in items),
        "bucket_seconds": bucket_seconds if section == "activity" else None,
        "bucket_semantics": "sparse_half_open_elapsed_intervals_no_empty_bucket_inference"
        if section == "activity"
        else None,
        "comparison_summary": summary if comparing else None,
        "comparison_basis": "exact_inventory_identity_without_pid_matching_or_rate_normalization"
        if comparing
        else None,
        "limitations": LIMITATIONS,
    }


def review(factory, settings, case_id, sample_id, report_id, user_id, **query):
    document, sources, source_hash = load(factory, settings, case_id, sample_id, report_id, user_id)
    result = derive(document, sources, settings, **query)
    result["source_report_sha256"] = source_hash
    raw = json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if len(raw) > settings.max_runtime_review_bytes:
        raise HTTPException(413, "Runtime review response exceeds configured bounds")
    return raw


def render(raw, limit):
    """Printable selected page, escaped throughout; no external resources or scripts."""
    data = json.loads(raw)
    parts, size = [], 0

    def append(value):
        nonlocal size
        encoded = value.encode("utf-8")
        size += len(encoded)
        if size > limit:
            raise HTTPException(413, "Runtime review HTML exceeds configured bounds")
        parts.append(encoded)

    def details(value):
        return (
            "<pre>"
            + escape(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True))
            + "</pre>"
        )

    append(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>GoDeEp runtime review</title>'
    )
    append("<style>" + STYLE + "</style><body><h1>GoDeEp runtime evidence review</h1>")
    append(
        '<p class="notice">Selected page of recorded collector claims. '
        "Coverage and attribution remain limited.</p>"
    )
    append(
        "<h2>Selection and provenance</h2>"
        + details({k: v for k, v in data.items() if k not in {"items", "sources", "limitations"}})
    )
    append("<h2>Sources and coverage</h2>" + details(data["sources"]))
    append("<h2>Inventory items</h2>")
    for item in data["items"]:
        append(details(item))
    append("<h2>Interpretation limits</h2>" + details(data["limitations"]))
    append("<p>Derived JSON SHA256: " + hashlib.sha256(raw).hexdigest() + "</p></body></html>")
    return b"".join(parts)
