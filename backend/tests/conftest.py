"""Isolated databases: SQLite by default, disposable PostgreSQL databases on opt-in."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from godeep.core.config import Settings
from godeep.main import create_app
from godeep.services.auth import create_user


@pytest.fixture
def database_url(tmp_path):
    admin_url = os.environ.get("GODEEP_TEST_POSTGRES_ADMIN_URL")
    if not admin_url:
        yield f"sqlite:///{(tmp_path / 'metadata.db').as_posix()}"
        return
    url = make_url(admin_url)
    if url.drivername != "postgresql+psycopg":
        raise ValueError("Tests require postgresql+psycopg for PostgreSQL")
    # A fresh database per test. Never migrate or drop the supplied admin database.
    name = "godeep_test_" + uuid4().hex
    admin = create_engine(url, isolation_level="AUTOCOMMIT")
    created = False
    try:
        with admin.connect() as connection:
            connection.execute(text(f'CREATE DATABASE "{name}" TEMPLATE template0'))
        created = True
        yield url.set(database=name).render_as_string(hide_password=False)
    finally:
        if created:
            # Only this locally generated, fixed-prefix identifier can be dropped.
            assert name.startswith("godeep_test_") and len(name) == 44
            with admin.connect() as connection:
                connection.execute(text(f'DROP DATABASE "{name}"'))
        admin.dispose()


@pytest.fixture
def intake(tmp_path, monkeypatch, database_url):
    monkeypatch.setenv("GODEEP_DATABASE_URL", database_url)
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=database_url,
        evidence_root=tmp_path / "evidence",
    )
    app = create_app(settings)
    create_user(app.state.sessions, "owner", "owner-test-password-123")
    with TestClient(app) as client:
        token = client.post(
            "/api/v1/auth/login", json={"username": "owner", "password": "owner-test-password-123"}
        ).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        yield client, app, config
