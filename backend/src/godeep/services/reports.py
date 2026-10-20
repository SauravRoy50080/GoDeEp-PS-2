"""Persisted JSON investigation snapshots from integrity-checked source results."""

import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import func, select

from godeep.core.security import aware
from godeep.persistence.models import (
    AnalysisJob,
    AuditEvent,
    ForensicReport,
    RuntimeCapture,
    Sample,
    new_id,
    utc_now,
)
from godeep.services.cases import require_case
from godeep.storage.artifacts import read_verified
from godeep.storage.runtime import read_trace


def require_sample(session, case_id, sample_id, user_id, *, write=False):
    case = require_case(session, case_id, user_id, write=write)
    sample = session.get(Sample, sample_id)
    if sample is None or sample.case_id != case_id:
        raise HTTPException(404, "Sample not found in this case")
    return case, sample


def require_report(session, case_id, sample_id, report_id, user_id):
    require_sample(session, case_id, sample_id, user_id)
    report = session.get(ForensicReport, report_id)
    if report is None or report.case_id != case_id or report.sample_id != sample_id:
        raise HTTPException(404, "Report not found for this sample")
    return report


def verify_original(root, sample, limit):
    try:
        path = (root / sample.storage_key).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Invalid original reference")
        digest, size = hashlib.sha256(), 0
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ValueError("Original exceeds operational bounds")
                digest.update(chunk)
        if digest.hexdigest() != sample.sha256 or size != sample.size_bytes:
            raise ValueError("Original bytes changed")
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Original evidence unavailable or integrity check failed") from exc


def create_report(factory, settings, case_id, sample_id, user_id, job_ids, capture_ids=()):
    destination = None
    owned_artifact = False
    root = settings.evidence_root.resolve()
    try:
        with factory.begin() as session:
            case, sample = require_sample(session, case_id, sample_id, user_id, write=True)
            jobs = []
            for job_id in sorted(str(value) for value in job_ids):
                job = session.get(AnalysisJob, job_id)
                if job is None or job.case_id != case_id or job.sample_id != sample_id:
                    raise HTTPException(404, "Source analysis not found for this sample")
                if job.status != "completed" or job.input_sha256 != sample.sha256:
                    raise HTTPException(409, "Sources must be completed analyses of this original")
                jobs.append(job)
            verify_original(root, sample, settings.max_upload_bytes)
            verified_at = utc_now()
            analyses, source_bytes = [], 0
            for job in jobs:
                raw = read_verified(
                    root, job.result_key, job.result_sha256, settings.max_result_bytes
                )
                source_bytes += len(raw)
                if source_bytes > settings.max_report_bytes:
                    raise HTTPException(413, "Selected analysis results exceed report bounds")
                try:
                    data = json.loads(raw)
                    if not isinstance(data, dict) or any(
                        data.get(key) != value
                        for key, value in (
                            ("schema_version", 1),
                            ("adapter", job.adapter),
                            ("adapter_version", job.adapter_version),
                            ("input_sha256", sample.sha256),
                        )
                    ):
                        raise ValueError("Source identity mismatch")
                except (ValueError, UnicodeError) as exc:
                    raise HTTPException(409, "Source analysis result is invalid") from exc
                analyses.append(
                    {
                        "job_id": job.id,
                        "adapter": job.adapter,
                        "adapter_version": job.adapter_version,
                        "completed_at": aware(job.finished_at).isoformat()
                        if job.finished_at
                        else None,
                        "result_sha256": job.result_sha256,
                        "configuration": job.config,
                        "data": data,
                    }
                )
            runtime_sources = []
            for capture_id in sorted(str(value) for value in capture_ids):
                capture = session.get(RuntimeCapture, capture_id)
                if capture is None or capture.case_id != case_id or capture.sample_id != sample_id:
                    raise HTTPException(404, "Source runtime capture not found for this sample")
                raw, trace = read_trace(
                    root, capture, sample.sha256, settings.max_runtime_capture_bytes
                )
                source_bytes += len(raw)
                if source_bytes > settings.max_report_bytes:
                    raise HTTPException(413, "Selected sources exceed report bounds")
                runtime_sources.append(
                    {
                        "capture_id": capture.id,
                        "artifact_sha256": capture.artifact_sha256,
                        "size_bytes": capture.size_bytes,
                        "imported_at": aware(capture.created_at).isoformat(),
                        "imported_by": capture.created_by,
                        "source_run_id": trace.source_run_id,
                        "attribution": "collector_asserted_not_verified",
                        "isolation": "not_verified",
                        "representation": "validated_normalized_trace_v1",
                        "data": trace.model_dump(mode="json"),
                    }
                )
            report_id, now = new_id(), utc_now()
            report_schema = 2 if runtime_sources else 1
            document = {
                "schema_version": report_schema,
                "report_id": report_id,
                "report_type": "investigation_analysis_snapshot",
                "generated_at": now.isoformat(),
                "created_by": user_id,
                "case": {"id": case.id, "name": case.name, "description": case.description},
                "sample": {
                    "id": sample.id,
                    "original_name": sample.original_name,
                    "sha256": sample.sha256,
                    "size_bytes": sample.size_bytes,
                    "original_verified_at": verified_at.isoformat(),
                },
                "selection": {
                    "source_job_ids": [job.id for job in jobs],
                    "analysis_count": len(jobs),
                    "scope": "Selected completed runs; not necessarily latest or exhaustive",
                },
                "analyses": analyses,
                "limitations": [
                    "Source coverage and confidence are preserved without upgrades",
                    "Overlapping analyzers can duplicate evidence without independent confirmation",
                    "Completed jobs can include partial phases or unavailable tools",
                    "No analyst sign-off, malware verdict or legal certification is generated",
                    "Hashes check against database metadata; custody is not tamper-proof",
                    "Original and source integrity were checked at report creation",
                ],
            }
            if runtime_sources:
                document["runtime_captures"] = runtime_sources
                document["selection"].update(
                    {
                        "source_capture_ids": [source["capture_id"] for source in runtime_sources],
                        "runtime_capture_count": len(runtime_sources),
                        "scope": "Explicitly selected analyses and imported collector traces only",
                    }
                )
                document["limitations"] += [
                    "Runtime attribution, package, times and isolation remain collector claims",
                    "Validated traces do not independently verify execution",
                    "Hashes identify source bytes; embedded traces use normalized JSON",
                    "Overlapping sources do not establish data flow or independent confirmation",
                    "Partial or failed collections and missing coverage remain incomplete",
                ]
            try:
                output = json.dumps(
                    document, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False
                ).encode("utf-8")
            except ValueError as exc:
                raise HTTPException(
                    409, "Source result cannot be represented in a strict JSON report"
                ) from exc
            if len(output) > settings.max_report_bytes:
                raise HTTPException(413, "Report exceeds configured output bounds")
            key = f"reports/{report_id}.json"
            destination = (root / key).resolve()
            if not destination.is_relative_to(root):
                raise HTTPException(409, "Invalid report storage reference")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as target:
                owned_artifact = True
                target.write(output)
            report = ForensicReport(
                id=report_id,
                case_id=case_id,
                sample_id=sample_id,
                created_by=user_id,
                source_job_ids=[job.id for job in jobs],
                input_sha256=sample.sha256,
                artifact_key=key,
                artifact_sha256=hashlib.sha256(output).hexdigest(),
                size_bytes=len(output),
                schema_version=report_schema,
                created_at=now,
            )
            session.add(report)
            session.add(
                AuditEvent(
                    case_id=case_id,
                    action="report.created",
                    actor=user_id,
                    subject_id=report_id,
                    details={
                        "sample_id": sample_id,
                        "artifact_sha256": report.artifact_sha256,
                        "source_job_ids": report.source_job_ids,
                        "source_capture_ids": [source["capture_id"] for source in runtime_sources],
                    },
                )
            )
            session.flush()
        return report
    except BaseException:
        if owned_artifact and destination is not None:
            destination.unlink(missing_ok=True)
        raise


def list_reports(factory, case_id, sample_id, user_id, limit, offset):
    with factory() as session:
        require_sample(session, case_id, sample_id, user_id)
        predicate = (ForensicReport.case_id == case_id) & (ForensicReport.sample_id == sample_id)
        total = session.scalar(select(func.count()).select_from(ForensicReport).where(predicate))
        rows = session.scalars(
            select(ForensicReport)
            .where(predicate)
            .order_by(ForensicReport.created_at.desc(), ForensicReport.id)
            .limit(limit)
            .offset(offset)
        ).all()
        return {"items": rows, "total": total, "limit": limit, "offset": offset}


def get_report(factory, case_id, sample_id, report_id, user_id):
    with factory() as session:
        return require_report(session, case_id, sample_id, report_id, user_id)


def download_report(factory, settings, case_id, sample_id, report_id, user_id):
    report = get_report(factory, case_id, sample_id, report_id, user_id)
    raw = read_verified(
        settings.evidence_root,
        report.artifact_key,
        report.artifact_sha256,
        settings.max_report_bytes,
    )
    if len(raw) != report.size_bytes:
        raise HTTPException(409, "Report size mismatch")
    return report, raw
