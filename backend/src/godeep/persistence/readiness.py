"""Credential-safe readiness probe for the configured local development database."""

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

from godeep.core.config import Settings
from godeep.persistence.database import build_engine


def database_reachable(port, settings=None):
    engine = None
    try:
        settings = settings or Settings()
        url = make_url(settings.database_url.get_secret_value())
        if (
            url.drivername != "postgresql+psycopg"
            or url.host not in {"localhost", "127.0.0.1"}
            or url.port != port
        ):
            return False
        engine = build_engine(settings.database_url.get_secret_value())
        with engine.connect() as connection:
            return connection.scalar(text("SELECT 1")) == 1
    except (SQLAlchemyError, ValueError, OSError):
        return False
    finally:
        if engine is not None:
            engine.dispose()
