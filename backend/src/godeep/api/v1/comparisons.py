"""Read-only comparison response; no persisted report or job is created."""

from uuid import UUID

from fastapi import APIRouter, Request, Response

from godeep.api.dependencies import CurrentUser
from godeep.schemas.comparisons import ComparisonCreate
from godeep.services.comparisons import compare_jobs

router = APIRouter(prefix="/cases/{case_id}/comparisons", tags=["sample comparisons"])


@router.post("", response_class=Response)
def create(case_id: UUID, payload: ComparisonCreate, request: Request, user: CurrentUser):
    raw = compare_jobs(
        request.app.state.sessions,
        request.app.state.settings,
        str(case_id),
        user.user_id,
        payload.left_job_id,
        payload.right_job_id,
    )
    return Response(raw, media_type="application/json", headers={"Cache-Control": "no-store"})
