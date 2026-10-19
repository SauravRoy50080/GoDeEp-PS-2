"""Durable jobs, scoped access, conditional claims and terminal transitions."""

from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from godeep.core.security import aware
from godeep.persistence.models import AnalysisJob, AuditEvent, Sample, new_id, utc_now
from godeep.schemas.jobs import JobCreate
from godeep.services.cases import require_case

ADAPTER_VERSION = "1.0.0"
TERMINAL = {"completed", "failed", "cancelled"}


def event(session, job, action, actor):
    session.add(
        AuditEvent(
            case_id=job.case_id,
            subject_id=job.id,
            actor=actor,
            action=action,
            details={
                "adapter": job.adapter,
                "attempt": job.attempt,
                "status": job.status,
                "error_code": job.error_code,
            },
        )
    )


def create_job(factory, settings, case_id, user_id, payload: JobCreate):
    with factory.begin() as session:
        require_case(session, case_id, user_id, write=True)
        sample = session.get(Sample, str(payload.sample_id))
        if sample is None or sample.case_id != case_id:
            raise HTTPException(404, "Sample not found in this case")
        config = {
            key: getattr(settings, key)
            for key in (
                "max_upload_bytes",
                "max_archive_entries",
                "max_uncompressed_bytes",
                "max_central_directory_bytes",
                "job_timeout_seconds",
            )
        }
        job = AnalysisJob(
            case_id=case_id,
            sample_id=sample.id,
            requested_by=user_id,
            adapter=payload.adapter,
            adapter_version=ADAPTER_VERSION,
            input_sha256=sample.sha256,
            config=config,
        )
        session.add(job)
        session.flush()
        event(session, job, "analysis.queued", user_id)
    return job


def require_job(session, case_id, job_id, user_id, *, write=False):
    require_case(session, case_id, user_id, write=write)
    job = session.get(AnalysisJob, job_id)
    if job is None or job.case_id != case_id:
        raise HTTPException(404, "Analysis job not found in this case")
    return job


def get_job(factory, case_id, job_id, user_id):
    with factory() as session:
        return require_job(session, case_id, job_id, user_id)


def list_jobs(factory, case_id, user_id, limit, offset):
    with factory() as session:
        require_case(session, case_id, user_id)
        query = select(AnalysisJob).where(AnalysisJob.case_id == case_id)
        rows = session.scalars(
            query.order_by(AnalysisJob.created_at.desc(), AnalysisJob.id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = session.scalar(
            select(func.count()).select_from(AnalysisJob).where(AnalysisJob.case_id == case_id)
        )
        return {"items": rows, "total": total, "limit": limit, "offset": offset}


def cancel_job(factory, case_id, job_id, user_id):
    with factory.begin() as session:
        require_job(session, case_id, job_id, user_id, write=True)
        changed = session.execute(
            update(AnalysisJob)
            .execution_options(synchronize_session=False)
            .where(AnalysisJob.id == job_id, AnalysisJob.status.in_(["queued", "running"]))
            .values(status="cancelled", finished_at=utc_now())
        ).rowcount
        session.expire_all()
        job = session.get(AnalysisJob, job_id)
        if not changed and job.status != "cancelled":
            raise HTTPException(409, "Only queued or running jobs can be cancelled")
        if changed:
            event(session, job, "analysis.cancelled", user_id)
    return job


def retry_job(factory, case_id, job_id, user_id):
    try:
        with factory.begin() as session:
            previous = require_job(session, case_id, job_id, user_id, write=True)
            if previous.status not in {"failed", "cancelled"} or previous.attempt >= 3:
                raise HTTPException(
                    409, "Retry requires a failed/cancelled job below three attempts"
                )
            job = AnalysisJob(
                case_id=case_id,
                sample_id=previous.sample_id,
                requested_by=user_id,
                adapter=previous.adapter,
                adapter_version=previous.adapter_version,
                config=dict(previous.config),
                input_sha256=previous.input_sha256,
                attempt=previous.attempt + 1,
                parent_id=previous.id,
            )
            session.add(job)
            session.flush()
            event(session, job, "analysis.retried", user_id)
        return job
    except IntegrityError as exc:
        raise HTTPException(409, "This job already has a retry") from exc


def claim_job(factory):
    with factory.begin() as session:
        job = session.scalar(
            select(AnalysisJob)
            .where(AnalysisJob.status == "queued")
            .order_by(AnalysisJob.created_at, AnalysisJob.id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job is None:
            return None
        token, now = new_id(), utc_now()
        # The conditional update also prevents duplicate claims in SQLite tests.
        changed = session.execute(
            update(AnalysisJob)
            .execution_options(synchronize_session=False)
            .where(AnalysisJob.id == job.id, AnalysisJob.status == "queued")
            .values(
                status="running",
                started_at=now,
                claim_token=token,
                lease_expires_at=now + timedelta(seconds=job.config["job_timeout_seconds"] + 30),
            )
        )
        if changed.rowcount != 1:
            return None
        session.refresh(job)
        event(session, job, "analysis.started", "analysis-worker")
    return job


def finish_job(
    factory, job_id, claim_token, *, error_code=None, result_key=None, result_sha256=None
):
    with factory.begin() as session:
        now = utc_now()
        changed = session.execute(
            update(AnalysisJob)
            .execution_options(synchronize_session=False)
            .where(
                AnalysisJob.id == job_id,
                AnalysisJob.claim_token == claim_token,
                AnalysisJob.status == "running",
                AnalysisJob.lease_expires_at > now,
            )
            .values(
                status="failed" if error_code else "completed",
                finished_at=now,
                error_code=error_code,
                result_key=result_key,
                result_sha256=result_sha256,
            )
        )
        if changed.rowcount != 1:
            return False
        job = session.get(AnalysisJob, job_id)
        session.refresh(job)
        event(
            session,
            job,
            "analysis.failed" if error_code else "analysis.completed",
            "analysis-worker",
        )
    return True


def expire_jobs(factory):
    count = 0
    with factory.begin() as session:
        jobs = session.scalars(
            select(AnalysisJob)
            .where(AnalysisJob.status == "running", AnalysisJob.lease_expires_at <= utc_now())
            .limit(100)
            .with_for_update(skip_locked=True)
        ).all()
        for job in jobs:
            changed = session.execute(
                update(AnalysisJob)
                .execution_options(synchronize_session=False)
                .where(
                    AnalysisJob.id == job.id,
                    AnalysisJob.status == "running",
                    AnalysisJob.lease_expires_at <= utc_now(),
                )
                .values(status="failed", error_code="worker_lease_expired", finished_at=utc_now())
            )
            if changed.rowcount:
                session.refresh(job)
                event(session, job, "analysis.failed", "analysis-worker")
                count += 1
    return count


def is_running(factory, job_id, claim_token):
    with factory() as session:
        job = session.get(AnalysisJob, job_id)
        return (
            job is not None
            and job.status == "running"
            and job.claim_token == claim_token
            and aware(job.lease_expires_at) > utc_now()
        )
