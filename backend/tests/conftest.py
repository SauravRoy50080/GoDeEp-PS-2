"""Isolated database/evidence fixtures; no real APKs or external services."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from godeep.core.config import Settings
from godeep.main import create_app
from godeep.services.auth import create_user


@pytest.fixture
def intake(tmp_path, monkeypatch):
    database_url = f"sqlite:///{(tmp_path / 'metadata.db').as_posix()}"
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
