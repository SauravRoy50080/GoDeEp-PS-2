"""Bounded runtime trace import and case-scoped verified downloads."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from starlette.concurrency import run_in_threadpool

from godeep.api.dependencies import CurrentUser
from godeep.schemas.intake import Page
from godeep.schemas.runtime_captures import CaptureRead
from godeep.services import runtime_captures as service

router = APIRouter(
    prefix="/cases/{case_id}/samples/{sample_id}/runtime-captures", tags=["runtime captures"]
)


@router.post(
    "",
    response_model=CaptureRead,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/RuntimeTrace"}}
            },
        }
    },
)
async def create(case_id: UUID, sample_id: UUID, request: Request, user: CurrentUser):
    factory, settings = request.app.state.sessions, request.app.state.settings
    await run_in_threadpool(service.authorize, factory, str(case_id), str(sample_id), user.user_id)
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Use application/json for runtime traces")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > settings.max_runtime_capture_bytes:
            raise HTTPException(413, "Runtime capture exceeds configured bounds")
        raw.extend(chunk)
    return await run_in_threadpool(
        service.create_capture,
        factory,
        settings,
        str(case_id),
        str(sample_id),
        user.user_id,
        bytes(raw),
    )


@router.get("", response_model=Page[CaptureRead])
def listing(
    case_id: UUID,
    sample_id: UUID,
    request: Request,
    user: CurrentUser,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return service.list_captures(
        request.app.state.sessions, str(case_id), str(sample_id), user.user_id, limit, offset
    )


@router.get("/{capture_id}", response_model=CaptureRead)
def metadata(case_id: UUID, sample_id: UUID, capture_id: UUID, request: Request, user: CurrentUser):
    return service.get_capture(
        request.app.state.sessions, str(case_id), str(sample_id), str(capture_id), user.user_id
    )


@router.get("/{capture_id}/download", response_class=Response)
def download(case_id: UUID, sample_id: UUID, capture_id: UUID, request: Request, user: CurrentUser):
    capture, raw = service.download_capture(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        str(capture_id),
        user.user_id,
    )
    return Response(
        raw,
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Capture-SHA256": capture.artifact_sha256,
            "Content-Disposition": f'attachment; filename="runtime-capture-{capture.id}.json"',
        },
    )
