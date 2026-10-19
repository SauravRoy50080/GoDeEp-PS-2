"""Version-one API route registration."""

from fastapi import APIRouter

from godeep.api.v1.health import router as health_router
from godeep.api.v1.intake import router as intake_router

router = APIRouter()
router.include_router(health_router)

router.include_router(intake_router)
