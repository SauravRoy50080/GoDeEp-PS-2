"""Case-authorized immutable storage of bounded collector-asserted runtime traces."""

import hashlib
from collections import Counter

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from godeep.persistence.models import AuditEvent, RuntimeCapture, new_id, utc_now
from godeep.schemas.runtime_captures import decode_trace
from godeep.services.reports import require_sample, verify_original
from godeep.storage.artifacts import read_verified


def authorize(factory, case_id, sample_id, user_id):
    with factory() as session:
        require_sample(session, case_id, sample_id, user_id, write=True)


def parse_trace(raw):
    try:
        return decode_trace(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise HTTPException(
            422, "Invalid runtime trace schema, coverage or event chronology"
        ) from exc


def create_capture(factory, settings, case_id, sample_id, user_id, raw):
    destination, owned = None, False
    root = settings.evidence_root.resolve()
    try:
        with factory.begin() as session:
            _, sample = require_sample(session, case_id, sample_id, user_id, write=True)
            if len(raw) > settings.max_runtime_capture_bytes:
                raise HTTPException(413, "Runtime capture exceeds configured bounds")
            trace = parse_trace(raw)
            if trace.input_sha256 != sample.sha256:
                raise HTTPException(409, "Trace input hash does not match this sample")
            verify_original(root, sample, settings.max_upload_bytes)
            counts = Counter(event.kind for event in trace.events)
            summary = {
                "event_count": len(trace.events),
                "event_counts": {
                    name: counts[name]
                    for name in ("process", "filesystem", "network", "sensitive_access")
                },
                "collection_status": trace.collection_status,
                "collector": trace.collector.model_dump(),
                "environment": trace.environment,
                "package_name": trace.package_name,
                "started_at": trace.started_at.isoformat(),
                "ended_at": trace.ended_at.isoformat(),
                "coverage": trace.coverage.model_dump(),
                "attribution": "collector_asserted_not_verified",
                "isolation": "not_verified",
                "interpretation": "Empty events do not establish absence of runtime activity",
                "original_integrity_checked_at": utc_now().isoformat(),
            }
            digest = hashlib.sha256(raw).hexdigest()
            duplicate = session.scalar(
                select(RuntimeCapture.id).where(
                    RuntimeCapture.sample_id == sample_id, RuntimeCapture.artifact_sha256 == digest
                )
            )
            if duplicate:
                raise HTTPException(409, "Identical trace already imported for this sample")
            capture_id = new_id()
            key = f"runtime-captures/{capture_id}.json"
            destination = (root / key).resolve()
            if not destination.is_relative_to(root):
                raise HTTPException(409, "Invalid capture storage reference")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as target:
                owned = True
                target.write(raw)
            capture = RuntimeCapture(
                id=capture_id,
                case_id=case_id,
                sample_id=sample_id,
                created_by=user_id,
                input_sha256=sample.sha256,
                source_run_id=trace.source_run_id,
                artifact_key=key,
                artifact_sha256=digest,
                size_bytes=len(raw),
                summary=summary,
            )
            session.add(capture)
            session.add(
                AuditEvent(
                    case_id=case_id,
                    actor=user_id,
                    subject_id=capture_id,
                    action="runtime_capture.imported",
                    details={
                        "sample_id": sample_id,
                        "artifact_sha256": digest,
                        "event_count": len(trace.events),
                        "attribution": "collector_asserted_not_verified",
                    },
                )
            )
            session.flush()
        return capture
    except BaseException as exc:
        if owned and destination is not None:
            destination.unlink(missing_ok=True)
        if isinstance(exc, (IntegrityError, OSError)):
            raise HTTPException(
                409, "Runtime capture could not be stored or already exists"
            ) from exc
        raise


def get_capture(factory, case_id, sample_id, capture_id, user_id):
    with factory() as session:
        require_sample(session, case_id, sample_id, user_id)
        capture = session.get(RuntimeCapture, capture_id)
        if capture is None or capture.case_id != case_id or capture.sample_id != sample_id:
            raise HTTPException(404, "Runtime capture not found for this sample")
        return capture


def list_captures(factory, case_id, sample_id, user_id, limit, offset):
    with factory() as session:
        require_sample(session, case_id, sample_id, user_id)
        predicate = (RuntimeCapture.case_id == case_id) & (RuntimeCapture.sample_id == sample_id)
        total = session.scalar(select(func.count()).select_from(RuntimeCapture).where(predicate))
        rows = session.scalars(
            select(RuntimeCapture)
            .where(predicate)
            .order_by(RuntimeCapture.created_at.desc(), RuntimeCapture.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return {"items": rows, "total": total, "limit": limit, "offset": offset}


def download_capture(factory, settings, case_id, sample_id, capture_id, user_id):
    capture = get_capture(factory, case_id, sample_id, capture_id, user_id)
    raw = read_verified(
        settings.evidence_root,
        capture.artifact_key,
        capture.artifact_sha256,
        settings.max_runtime_capture_bytes,
    )
    if len(raw) != capture.size_bytes:
        raise HTTPException(409, "Runtime capture size mismatch")
    return capture, raw
