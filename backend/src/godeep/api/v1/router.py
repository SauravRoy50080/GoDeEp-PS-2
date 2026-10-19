"""Version-one API route registration."""

from fastapi import APIRouter

from godeep.api.v1.auth import router as auth_router
from godeep.api.v1.health import router as health_router
from godeep.api.v1.intake import router as intake_router
from godeep.api.v1.jobs import router as jobs_router
from godeep.api.v1.members import router as members_router

router = APIRouter()
router.include_router(health_router)

router.include_router(intake_router)

router.include_router(auth_router)
router.include_router(members_router)

router.include_router(jobs_router)
