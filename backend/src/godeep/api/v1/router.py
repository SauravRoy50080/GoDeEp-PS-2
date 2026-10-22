"""Version-one API route registration."""

from fastapi import APIRouter

from godeep.api.v1.analyzers import router as analyzers_router
from godeep.api.v1.auth import router as auth_router
from godeep.api.v1.capabilities import router as capabilities_router
from godeep.api.v1.comparisons import router as comparisons_router
from godeep.api.v1.health import router as health_router
from godeep.api.v1.intake import router as intake_router
from godeep.api.v1.jobs import router as jobs_router
from godeep.api.v1.members import router as members_router
from godeep.api.v1.report_reviews import router as reviews_router
from godeep.api.v1.reports import router as reports_router
from godeep.api.v1.runtime_captures import router as captures_router
from godeep.api.v1.timeline import router as timeline_router

router = APIRouter()
router.include_router(health_router)

router.include_router(intake_router)

router.include_router(auth_router)
router.include_router(members_router)

router.include_router(jobs_router)

router.include_router(analyzers_router)
router.include_router(capabilities_router)

router.include_router(reports_router)
router.include_router(reviews_router)

router.include_router(comparisons_router)

router.include_router(captures_router)

router.include_router(timeline_router)
