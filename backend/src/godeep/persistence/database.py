"""Engine/session factories; schema changes belong to Alembic, not API startup."""

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker


def build_engine(url: str) -> Engine:
    options = (
        {"check_same_thread": False}
        if url.startswith("sqlite")
        else {"connect_timeout": 5}
        if url.startswith("postgresql+psycopg")
        else {}
    )
    engine = create_engine(url, pool_pre_ping=True, connect_args=options)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

    return engine


def session_factory(engine: Engine):
    return sessionmaker(bind=engine, expire_on_commit=False)
