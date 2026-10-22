"""Process liveness; dependency readiness will be a separate endpoint."""

from fastapi import APIRouter, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from godeep.schemas.health import LivenessResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=LivenessResponse)
def liveness() -> LivenessResponse:
    return LivenessResponse()


@router.get("/ready")
def readiness(request: Request, response: Response):
    try:
        with request.app.state.engine.connect() as connection:
            versions = (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalars().all()
            )
        ready = versions == ["0006_report_reviews"]
    except SQLAlchemyError:
        ready = False
    if not ready:
        response.status_code = 503
    return {
        "ready": ready,
        "scope": "metadata_database_and_required_schema_only",
        "sandbox_ready": False,
        "production_ml_ready": False,
    }
