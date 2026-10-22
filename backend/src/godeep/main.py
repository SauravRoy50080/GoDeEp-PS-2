"""Local-development API. Apply migrations before using persistence endpoints."""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from godeep.api.openapi import document_runtime_upload
from godeep.api.v1.router import router
from godeep.core.config import Settings
from godeep.core.http_guard import HttpGuard
from godeep.persistence.database import build_engine, session_factory
from godeep.storage.local import LocalEvidenceStore


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(application):
        yield
        application.state.engine.dispose()

    docs = (
        settings.docs_enabled
        if settings.docs_enabled is not None
        else settings.environment != "production"
    )
    application = FastAPI(
        title=settings.app_name,
        version="0.35.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    engine = build_engine(settings.database_url.get_secret_value())
    application.state.settings = settings
    application.state.engine = engine
    application.state.sessions = session_factory(engine)
    application.state.evidence_store = LocalEvidenceStore(settings.evidence_root)

    @application.exception_handler(SQLAlchemyError)
    async def database_error(_request: Request, _error: SQLAlchemyError):
        return JSONResponse(status_code=503, content={"detail": "Database operation unavailable"})

    @application.exception_handler(OSError)
    async def storage_error(_request: Request, _error: OSError):
        return JSONResponse(status_code=503, content={"detail": "Evidence storage unavailable"})

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, error: RequestValidationError):
        # Never echo submitted credentials or arbitrary request values in error bodies.
        errors = [
            {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in error.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @application.middleware("http")
    async def private_responses(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/v1/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    application.include_router(router, prefix="/api/v1")
    document_runtime_upload(application)
    application.add_middleware(HttpGuard, settings=settings)
    hosts = list(settings.allowed_hosts)
    if settings.environment != "production" and "testserver" not in hosts:
        hosts.append("testserver")
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts, www_redirect=False)
    if settings.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Filename"],
            allow_credentials=False,
            expose_headers=["X-Request-ID", "X-Export-SHA256", "X-Source-Report-SHA256"],
        )
    return application


app = create_app()
