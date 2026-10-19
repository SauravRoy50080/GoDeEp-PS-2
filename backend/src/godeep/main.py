"""API application factory. No analysis or external connections run at startup."""

from fastapi import FastAPI

from godeep.api.v1.router import router
from godeep.core.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    application = FastAPI(title=settings.app_name, version="0.1.0")
    application.include_router(router, prefix="/api/v1")
    return application


app = create_app()
