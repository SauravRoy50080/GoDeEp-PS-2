"""Authenticated, case-scoped analysis submission and verified result access."""

import hashlib
import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request

from godeep.api.dependencies import CurrentUser
from godeep.schemas.intake import Page
from godeep.schemas.jobs import JobCreate, JobRead, JobResult
from godeep.services import jobs

router = APIRouter(prefix="/cases/{case_id}/analyses", tags=["analysis jobs"])


@router.post("", response_model=JobRead, status_code=202)
def create_job(case_id: UUID, payload: JobCreate, request: Request, user: CurrentUser):
    return jobs.create_job(
        request.app.state.sessions, request.app.state.settings, str(case_id), user.user_id, payload
    )


@router.get("", response_model=Page[JobRead])
def list_jobs(
    case_id: UUID,
    request: Request,
    user: CurrentUser,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return jobs.list_jobs(request.app.state.sessions, str(case_id), user.user_id, limit, offset)


@router.get("/{job_id}", response_model=JobRead)
def get_job(case_id: UUID, job_id: UUID, request: Request, user: CurrentUser):
    return jobs.get_job(request.app.state.sessions, str(case_id), str(job_id), user.user_id)


@router.post("/{job_id}/cancel", response_model=JobRead)
def cancel_job(case_id: UUID, job_id: UUID, request: Request, user: CurrentUser):
    return jobs.cancel_job(request.app.state.sessions, str(case_id), str(job_id), user.user_id)


@router.post("/{job_id}/retry", response_model=JobRead, status_code=202)
def retry_job(case_id: UUID, job_id: UUID, request: Request, user: CurrentUser):
    return jobs.retry_job(request.app.state.sessions, str(case_id), str(job_id), user.user_id)


@router.get("/{job_id}/result", response_model=JobResult)
def result(case_id: UUID, job_id: UUID, request: Request, user: CurrentUser):
    job = jobs.get_job(request.app.state.sessions, str(case_id), str(job_id), user.user_id)
    if job.status != "completed":
        raise HTTPException(409, "Result is available only for a completed job")
    settings = request.app.state.settings
    root = settings.evidence_root.resolve()
    path = (root / job.result_key).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(409, "Invalid result artifact reference")
    try:
        with path.open("rb") as source:
            raw = source.read(settings.max_result_bytes + 1)
        if (
            len(raw) > settings.max_result_bytes
            or hashlib.sha256(raw).hexdigest() != job.result_sha256
        ):
            raise HTTPException(409, "Result artifact integrity check failed")
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Result artifact unavailable or invalid") from exc
    return {
        "job_id": job.id,
        "adapter": job.adapter,
        "adapter_version": job.adapter_version,
        "input_sha256": job.input_sha256,
        "result_sha256": job.result_sha256,
        "data": data,
    }
