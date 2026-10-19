"""Check the public API scaffold without external services."""

from fastapi.testclient import TestClient

from godeep.core.config import Settings
from godeep.main import create_app


def test_liveness_contract():
    app = create_app(Settings(_env_file=None, environment="test"))
    with TestClient(app) as client:
        response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
