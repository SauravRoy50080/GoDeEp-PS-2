"""Append-only, evidence-bound analyst review threads, separate from source reports."""

import hashlib
import json
import re
from html import escape

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from godeep.persistence.models import AuditEvent, ForensicReport, ReportReviewEntry, new_id
from godeep.schemas.report_reviews import EvidenceReference, ReviewRead
from godeep.services.cases import require_case
from godeep.services.report_html import STYLE
from godeep.services.reports import require_report
from godeep.services.runtime_review import validate as validate_captures
from godeep.storage.artifacts import read_verified

VERSION = "1.0.0"
LIMITATIONS = [
    "Entries are analyst judgments, not independently verified facts or malware verdicts",
    "Source evidence and collector attribution retain their original limitations",
    "Revisions replace the complete entry in its thread; prior entries remain in history",
    "Other threads may disagree; current entries are not consensus or report approval",
    "Authors are account IDs; no digital signature, legal attestation or tamper-proof custody",
    "Append-only through this API; privileged database changes are not cryptographically prevented",
    "Pointers address normalized snapshot values, not original trace byte offsets",
    "Original APK and source integrity were checked at report creation, not re-read here",
]


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate snapshot key")
        result[key] = value
    return result


def _invalid(value):
    raise ValueError("Non-finite snapshot value")


def document(report, settings):
    raw = read_verified(
        settings.evidence_root,
        report.artifact_key,
        report.artifact_sha256,
        settings.max_report_bytes,
    )
    try:
        data = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid)
        if (
            len(raw) != report.size_bytes
            or type(data["schema_version"]) is not int
            or data["schema_version"] not in (1, 2)
            or data["schema_version"] != report.schema_version
            or data["report_type"] != "investigation_analysis_snapshot"
            or data["report_id"] != report.id
            or data["case"]["id"] != report.case_id
            or data["sample"]["id"] != report.sample_id
            or data["sample"]["sha256"] != report.input_sha256
            or not isinstance(data["analyses"], list)
            or not isinstance(data.get("runtime_captures", []), list)
            or not 1 <= len(data["analyses"]) + len(data.get("runtime_captures", [])) <= 20
            or (data["schema_version"] == 1 and data.get("runtime_captures"))
        ):
            raise ValueError("Snapshot identity mismatch")
        if data.get("runtime_captures"):
            validate_captures(data)
        return data
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise HTTPException(409, "Report snapshot is invalid for analyst review") from exc


def tokens(pointer):
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("Invalid JSON pointer")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    if len(parts) > 32:
        raise ValueError("Evidence pointer too deep")
    return parts


def resolve(data, parts):
    for part in parts:
        if isinstance(data, dict):
            data = data[part]
        elif isinstance(data, list) and re.fullmatch(r"0|[1-9][0-9]{0,8}", part):
            data = data[int(part)]
        else:
            raise ValueError("Pointer does not resolve")
    return data


class Binder:
    def __init__(self, data, settings):
        self.data, self.settings, self.cache, self.bytes = data, settings, {}, 0

    def bind(self, reference):
        key = (reference.source_kind, str(reference.source_id), reference.pointer)
        if key in self.cache:
            return self.cache[key]
        try:
            parts = tokens(reference.pointer)
            collection, id_key, hash_key = (
                ("analyses", "job_id", "result_sha256")
                if reference.source_kind == "analysis"
                else ("runtime_captures", "capture_id", "artifact_sha256")
            )
            if len(parts) < 3 or parts[0] != collection or parts[2] != "data":
                raise ValueError("Only source data may be referenced")
            source = resolve(self.data, parts[:2])
            if source[id_key] != str(reference.source_id) or not re.fullmatch(
                r"[a-f0-9]{64}", source[hash_key]
            ):
                raise ValueError("Source identity mismatch")
            if source["data"]["input_sha256"] != self.data["sample"]["sha256"]:
                raise ValueError("Source sample mismatch")
            if reference.source_kind == "analysis" and (
                source["data"]["adapter"] != source["adapter"]
                or source["data"]["adapter_version"] != source["adapter_version"]
            ):
                raise ValueError("Analysis identity mismatch")
            raw = encode(resolve(self.data, parts))
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, RecursionError) as exc:
            raise HTTPException(
                422, "Evidence reference does not resolve to the selected source"
            ) from exc
        self.bytes += len(raw)
        if self.bytes > self.settings.max_report_review_reference_bytes:
            raise HTTPException(413, "Referenced snapshot values exceed review byte budget")
        result = {
            **reference.model_dump(mode="json"),
            "source_sha256": source[hash_key],
            "snapshot_value_sha256": digest(raw),
            "value_hash_encoding": "sorted_ascii_json_v1",
        }
        self.cache[key] = result
        return result


def create(factory, settings, case_id, sample_id, report_id, user_id, payload):
    try:
        with factory.begin() as session:
            case = require_case(session, case_id, user_id, write=True)
            report = require_report(session, case_id, sample_id, report_id, user_id)
            if payload.expected_report_sha256 != report.artifact_sha256:
                raise HTTPException(409, "Report hash differs from the reviewed snapshot")
            data = document(report, settings)
            binder = Binder(data, settings)
            references = [binder.bind(ref) for ref in payload.evidence_references]
            parent, thread_id = None, None
            if payload.supersedes_id:
                parent = session.get(ReportReviewEntry, str(payload.supersedes_id))
                if parent is None or parent.report_id != report_id:
                    raise HTTPException(404, "Review entry not found in this report")
                root = session.get(ReportReviewEntry, parent.thread_id)
                if root is None or root.report_id != report_id or root.supersedes_id is not None:
                    raise HTTPException(409, "Review thread is invalid")
                if root.created_by != user_id and case.owner_id != user_id:
                    raise HTTPException(403, "Only the thread author or case owner may revise it")
                if parent.report_sha256 != report.artifact_sha256 or session.scalar(
                    select(ReportReviewEntry.id).where(ReportReviewEntry.supersedes_id == parent.id)
                ):
                    raise HTTPException(409, "Review entry is stale or belongs to another snapshot")
                thread_id = root.id
            allocated = session.execute(
                update(ForensicReport)
                .where(
                    ForensicReport.id == report_id,
                    ForensicReport.review_entry_count < settings.max_report_review_entries,
                )
                .values(review_entry_count=ForensicReport.review_entry_count + 1)
            )
            if allocated.rowcount != 1:
                raise HTTPException(413, "Report review entry budget exceeded")
            entry_id = new_id()
            entry = ReportReviewEntry(
                id=entry_id,
                report_id=report_id,
                thread_id=thread_id or entry_id,
                supersedes_id=parent.id if parent else None,
                created_by=user_id,
                report_sha256=report.artifact_sha256,
                decision=payload.decision,
                text=payload.text,
                evidence_references=references,
            )
            session.add(entry)
            session.add(
                AuditEvent(
                    case_id=case_id,
                    actor=user_id,
                    action="report.review_appended",
                    subject_id=entry_id,
                    details={
                        "report_id": report_id,
                        "thread_id": entry.thread_id,
                        "supersedes_id": entry.supersedes_id,
                        "report_sha256": report.artifact_sha256,
                        "decision": entry.decision,
                        "reference_count": len(references),
                    },
                )
            )
            session.flush()
        return entry
    except IntegrityError as exc:
        raise HTTPException(
            409, "Review changed concurrently; reload the thread before revising"
        ) from exc
    except OperationalError as exc:
        raise HTTPException(
            503, "Review storage temporarily unavailable; reload before retrying"
        ) from exc


def snapshot(factory, settings, case_id, sample_id, report_id, user_id):
    with factory() as session:
        report = require_report(session, case_id, sample_id, report_id, user_id)
        data = document(report, settings)
        entries = session.scalars(
            select(ReportReviewEntry)
            .where(ReportReviewEntry.report_id == report_id)
            .order_by(ReportReviewEntry.created_at, ReportReviewEntry.id)
            .limit(settings.max_report_review_entries + 1)
        ).all()
    if len(entries) > settings.max_report_review_entries:
        raise HTTPException(413, "Report review entry budget exceeded")
    binder = Binder(data, settings)
    ids = {entry.id: entry for entry in entries}
    children = set()
    try:
        for entry in entries:
            if entry.report_sha256 != report.artifact_sha256:
                raise ValueError("Review snapshot hash mismatch")
            if entry.supersedes_id:
                parent = ids[entry.supersedes_id]
                if parent.thread_id != entry.thread_id or parent.id in children:
                    raise ValueError("Invalid review lineage")
                children.add(parent.id)
            elif entry.thread_id != entry.id:
                raise ValueError("Invalid review root")
            # Follow parent links to reject cycles without relying on host clock ordering.
            cursor, seen = entry, set()
            while cursor.supersedes_id:
                if cursor.id in seen:
                    raise ValueError("Review cycle")
                seen.add(cursor.id)
                cursor = ids[cursor.supersedes_id]
            if cursor.id != entry.thread_id:
                raise ValueError("Review root mismatch")
            if len(entry.evidence_references) > 10 or entry.decision not in {
                "comment",
                "supported",
                "disputed",
                "follow_up",
            }:
                raise ValueError("Review record invalid")
            for stored in entry.evidence_references:
                ref = EvidenceReference.model_validate(
                    {key: stored[key] for key in ("source_kind", "source_id", "pointer")}
                )
                if binder.bind(ref) != stored:
                    raise ValueError("Review evidence binding changed")
        return report, entries, children
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise HTTPException(
            409, "Stored review history is inconsistent with this snapshot"
        ) from exc
    except HTTPException as exc:
        if exc.status_code == 422:
            raise HTTPException(409, "Stored review evidence reference is invalid") from exc
        raise


def listing(
    factory,
    settings,
    case_id,
    sample_id,
    report_id,
    user_id,
    *,
    current=False,
    thread_id=None,
    limit=25,
    offset=0,
):
    report, entries, children = snapshot(factory, settings, case_id, sample_id, report_id, user_id)
    if thread_id and not any(entry.thread_id == thread_id for entry in entries):
        raise HTTPException(404, "Review thread not found in this report")
    selected = [
        entry
        for entry in entries
        if (not current or entry.id not in children)
        and (not thread_id or entry.thread_id == thread_id)
    ]
    result = {
        "items": [
            ReviewRead.model_validate(entry).model_dump(mode="json")
            for entry in selected[offset : offset + limit]
        ],
        "total": len(selected),
        "limit": limit,
        "offset": offset,
        "view": "current_thread_heads" if current else "append_only_history",
        "source_report_sha256": report.artifact_sha256,
        "review_version": VERSION,
        "limitations": LIMITATIONS,
    }
    raw = encode(result)
    if len(raw) > settings.max_report_review_bytes:
        raise HTTPException(413, "Review response exceeds configured byte budget")
    return raw


def export(factory, settings, case_id, sample_id, report_id, user_id):
    raw = listing(
        factory,
        settings,
        case_id,
        sample_id,
        report_id,
        user_id,
        limit=settings.max_report_review_entries,
    )
    data = json.loads(raw)
    data.update(
        schema_version=1,
        report_id=report_id,
        case_id=case_id,
        sample_id=sample_id,
        current_entry_ids=sorted(
            set(item["id"] for item in data["items"])
            - {item["supersedes_id"] for item in data["items"] if item["supersedes_id"]}
        ),
    )
    raw = encode(data)
    if len(raw) > settings.max_report_review_bytes:
        raise HTTPException(413, "Review export exceeds configured byte budget")
    return raw


def render(raw, limit):
    data = json.loads(raw)
    parts, size = [], 0

    def append(value):
        nonlocal size
        encoded = value.encode("utf-8")
        size += len(encoded)
        if size > limit:
            raise HTTPException(413, "Review HTML exceeds configured byte budget")
        parts.append(encoded)

    def details(value):
        return (
            "<pre>"
            + escape(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True))
            + "</pre>"
        )

    append(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>GoDeEp analyst reviews</title>'
    )
    append("<style>" + STYLE + "</style><body><h1>Analyst review history</h1>")
    append(
        '<p class="notice">Analyst judgments alongside evidence. '
        "No report approval or malware verdict.</p>"
    )
    append(details({key: value for key, value in data.items() if key != "items"}))
    for entry in data["items"]:
        append(
            "<h2>"
            + ("Current entry" if entry["id"] in data["current_entry_ids"] else "Superseded entry")
            + "</h2>"
        )
        append(details(entry))
    append("<p>Review JSON SHA256: " + digest(raw) + "</p></body></html>")
    return b"".join(parts)
