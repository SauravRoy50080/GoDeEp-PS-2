"""Process liveness; dependency readiness will be a separate endpoint."""

from fastapi import APIRouter

from godeep.schemas.health import LivenessResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse)
def liveness() -> LivenessResponse:
    return LivenessResponse()
