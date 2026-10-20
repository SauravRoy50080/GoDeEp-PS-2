"""Read-only, explicitly selected sample runtime chronology."""

from uuid import UUID

from fastapi import APIRouter, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.timeline import TimelineQuery
from godeep.services.timeline import runtime_timeline

router = APIRouter(tags=["runtime timeline"])


@router.post("/cases/{case_id}/samples/{sample_id}/runtime-timeline", response_class=Response)
def timeline(
    case_id: UUID, sample_id: UUID, payload: TimelineQuery, request: Request, user: CurrentUser
):
    raw = runtime_timeline(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        str(sample_id),
        user.user_id,
        payload,
    )
    return Response(
        raw,
        media_type="application/json",
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
