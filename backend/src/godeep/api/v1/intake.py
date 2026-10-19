"""Local-development intake API. Authorization is a later milestone."""

import hashlib
import os
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from godeep.analysis.static.archive import InvalidAPK
from godeep.persistence.models import AuditEvent, Case, Sample
from godeep.schemas.intake import AuditRead, CaseCreate, CaseRead, Page, SampleRead
from godeep.services import cases
from godeep.services.intake import register_sample

router = APIRouter(tags=["evidence intake"])


@router.post("/cases", response_model=CaseRead, status_code=201)
def create_case(payload: CaseCreate, request: Request):
    return cases.create_case(request.app.state.sessions, payload)


@router.get("/cases", response_model=Page[CaseRead])
def list_cases(
    request: Request, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)
):
    return cases.list_records(request.app.state.sessions, Case, limit, offset)


@router.get("/cases/{case_id}", response_model=CaseRead)
def get_case(case_id: UUID, request: Request):
    return cases.get_case(request.app.state.sessions, str(case_id))


@router.get("/cases/{case_id}/samples", response_model=Page[SampleRead])
def list_samples(
    case_id: UUID,
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return cases.list_records(request.app.state.sessions, Sample, limit, offset, str(case_id))


@router.get("/cases/{case_id}/samples/{sample_id}", response_model=SampleRead)
def get_sample(case_id: UUID, sample_id: UUID, request: Request):
    return cases.get_sample(request.app.state.sessions, str(case_id), str(sample_id))


@router.get("/cases/{case_id}/audit", response_model=Page[AuditRead])
def list_audit(
    case_id: UUID,
    request: Request,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return cases.list_records(request.app.state.sessions, AuditEvent, limit, offset, str(case_id))


@router.post(
    "/cases/{case_id}/samples",
    response_model=SampleRead,
    status_code=201,
    summary="Register original APK bytes (not multipart)",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
        }
    },
)
async def upload_sample(case_id: UUID, request: Request, x_filename: str = Header(...)):
    settings = request.app.state.settings
    factory = request.app.state.sessions
    store = request.app.state.evidence_store
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/octet-stream", "application/vnd.android.package-archive"}:
        raise HTTPException(415, "Send raw APK bytes, not a multipart form")
    if (
        not x_filename.lower().endswith(".apk")
        or len(x_filename) > 255
        or any(c in x_filename for c in "/\\:")
        or any(ord(c) < 32 or ord(c) == 127 for c in x_filename)
    ):
        raise HTTPException(
            422, "X-Filename must be a plain .apk filename (maximum 255 characters)"
        )
    await run_in_threadpool(cases.get_case, factory, str(case_id))
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdecimal():
            raise HTTPException(400, "Invalid Content-Length")
        if len(declared) > 20 or int(declared) > settings.max_upload_bytes:
            raise HTTPException(413, "APK exceeds configured upload limit")
    sample_id = str(uuid4())
    staged = None
    size = 0
    digest = hashlib.sha256()
    try:
        handle = await run_in_threadpool(store.stage)
        staged = Path(handle.name)
        try:
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, "APK exceeds configured upload limit")
                digest.update(chunk)
                await run_in_threadpool(handle.write, chunk)
            if size == 0:
                raise HTTPException(422, "Empty APK body")
            if declared is not None and int(declared) != size:
                raise HTTPException(400, "Content-Length does not match body")
            await run_in_threadpool(handle.flush)
            await run_in_threadpool(os.fsync, handle.fileno())
        finally:
            await run_in_threadpool(handle.close)
        return await run_in_threadpool(
            register_sample,
            factory,
            store,
            settings,
            str(case_id),
            sample_id,
            x_filename,
            staged,
            digest.hexdigest(),
            size,
        )
    except InvalidAPK as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        if staged is not None:
            await run_in_threadpool(staged.unlink, missing_ok=True)
