"""Production settings, request limits, readiness and cryptographic evidence handoff."""

import asyncio
import io
import json
from zipfile import ZipFile

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from test_report_reviews import setup

from godeep.core.config import Settings
from godeep.core.http_guard import HttpGuard
from godeep.main import create_app
from godeep.reporting import evidence_package as package


def test_production_configuration_fails_closed(tmp_path):
    for kwargs in [
        {},
        {"database_url": "sqlite:///example.db"},
        {"database_url": "postgresql+psycopg://u:p@localhost/x", "allowed_hosts": ["*"]},
    ]:
        with pytest.raises(ValueError):
            Settings(_env_file=None, environment="production", **kwargs)
    settings = Settings(
        _env_file=None,
        environment="production",
        database_url="postgresql+psycopg://u:private-test-password@localhost/x",
        evidence_root=tmp_path,
    )
    app = create_app(settings)
    with TestClient(app, base_url="http://localhost") as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/api/v1/health/live").status_code == 200
        assert (
            client.get("/api/v1/health/live", headers={"Host": "untrusted.example"}).status_code
            == 400
        )


def test_exact_cors_headers_and_json_limits(intake):
    client, app, _ = intake
    app.state.settings.max_json_request_bytes = 1024
    result = client.post("/api/v1/cases", content=b" " * 1025)
    assert result.status_code == 413
    assert result.headers["x-content-type-options"] == "nosniff"
    assert len(result.headers["x-request-id"]) == 32
    result = client.post("/api/v1/cases", content=(chunk for chunk in [b" " * 800, b" " * 800]))
    assert result.status_code == 413
    assert client.get("/api/v1/health/ready").json()["ready"] is True
    capabilities = client.get("/api/v1/capabilities").json()
    assert capabilities["ml"]["production_inference"] == "unavailable"
    assert capabilities["runtime"]["isolated_apk_execution"].startswith("unavailable")
    client.headers.pop("Authorization")
    assert client.get("/api/v1/capabilities").status_code == 401


def test_cors_allows_only_configured_origin():
    settings = Settings(_env_file=None, cors_origins=["http://localhost:5173"])
    with TestClient(create_app(settings)) as client:
        good = client.options(
            "/api/v1/cases",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        assert (
            good.status_code == 200
            and good.headers["access-control-allow-origin"] == "http://localhost:5173"
        )
        bad = client.options(
            "/api/v1/cases",
            headers={"Origin": "https://other.example", "Access-Control-Request-Method": "POST"},
        )
        assert bad.status_code == 400 and "access-control-allow-origin" not in bad.headers
    for origin in ["*", "https://example.org/path", "https://example.org?key=x"]:
        with pytest.raises(ValueError):
            Settings(_env_file=None, cors_origins=[origin])


def test_duplicate_and_invalid_content_lengths_are_rejected():
    async def exercise(headers):
        sent = []

        async def app(scope, receive, send):
            raise AssertionError("inner app should not receive invalid headers")

        async def receive():
            raise AssertionError("body should not be consumed")

        async def send(message):
            sent.append(message)

        await HttpGuard(app, Settings(_env_file=None))(
            {"type": "http", "method": "POST", "path": "/api/v1/cases", "headers": headers},
            receive,
            send,
        )
        return sent[0]["status"]

    assert asyncio.run(exercise([(b"content-length", b"1"), (b"content-length", b"2")])) == 400
    assert asyncio.run(exercise([(b"content-length", b"invalid")])) == 400


def evidence(intake):
    client, _, _ = intake
    _, _, _, uri, _, payload = setup(intake)
    first = client.post(uri + "/reviews", json=payload).json()
    client.post(uri + "/reviews", json={**payload, "supersedes_id": first["id"]})
    response = client.get(uri + "/export/package")
    assert response.status_code == 200, response.text
    assert response.headers["x-export-sha256"] == package.digest(response.content)
    return response.content, uri


def test_canonical_package_signatures_pinned_key_and_no_source_mutation(intake):
    raw, uri = evidence(intake)
    meta = package.verify(raw)
    assert meta["scope"] == "recorded_report_and_analyst_reviews_only"
    with ZipFile(io.BytesIO(raw)) as z:
        assert set(z.namelist()) == package.MEMBERS
        original = z.read("report.json")
        reviews = json.loads(z.read("reviews.json"))
        assert len(reviews["items"]) == 2 and len(reviews["current_entry_ids"]) == 1
    key = Ed25519PrivateKey.generate()
    signed = package.signature(raw, key, "Synthetic signing operator")
    assert package.verify_signature(raw, signed, key.public_key())[
        "package_sha256"
    ] == package.digest(raw)
    with pytest.raises(ValueError):
        package.verify_signature(raw, signed, Ed25519PrivateKey.generate().public_key())
    tampered = json.loads(signed)
    tampered["signer_label"] = "Another operator"
    with pytest.raises(InvalidSignature):
        package.verify_signature(raw, package.encode(tampered), key.public_key())
    client, _, _ = intake
    assert client.get(uri + "/download").content == original


@pytest.mark.parametrize("mode", ["suffix", "prefix", "member", "review_hash", "heads"])
def test_package_tampering_rejected(intake, mode):
    raw, _ = evidence(intake)
    if mode == "suffix":
        changed = raw + b"extra"
    elif mode == "prefix":
        changed = b"extra" + raw
    else:
        with ZipFile(io.BytesIO(raw)) as z:
            values = {name: z.read(name) for name in z.namelist()}
        if mode in {"review_hash", "heads"}:
            doc = json.loads(values["reviews.json"])
            if mode == "review_hash":
                doc["items"][0]["report_sha256"] = "a" * 64
            else:
                doc["current_entry_ids"] = []
            with pytest.raises(ValueError):
                package.build(values["report.json"], package.encode(doc))
            return
        values["unexpected.json"] = b"{}"
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as z:
            for name, value in values.items():
                z.writestr(name, value)
        changed = buffer.getvalue()
    with pytest.raises(ValueError):
        package.verify(changed)


def test_encrypted_key_cli_requires_explicit_trusted_key(intake, tmp_path, monkeypatch, capsys):
    raw, _ = evidence(intake)
    artifact = tmp_path / "evidence.zip"
    artifact.write_bytes(raw)
    keys = tmp_path / "keys"
    monkeypatch.setenv("GODEEP_SIGNING_PASSPHRASE", "test-only-long-passphrase")
    assert package.main(["keygen", "--directory", str(keys)]) == 0
    assert b"ENCRYPTED PRIVATE KEY" in (keys / "private.pem").read_bytes()
    signed = tmp_path / "signature.json"
    assert (
        package.main(
            [
                "sign",
                "--package",
                str(artifact),
                "--private-key",
                str(keys / "private.pem"),
                "--output",
                str(signed),
                "--signer",
                "Test operator",
            ]
        )
        == 0
    )
    assert package.main(["verify", "--package", str(artifact), "--signature", str(signed)]) == 2
    assert (
        package.main(
            [
                "verify",
                "--package",
                str(artifact),
                "--signature",
                str(signed),
                "--trusted-public-key",
                str(keys / "public.pem"),
            ]
        )
        == 0
    )
    assert "test-only-long-passphrase" not in capsys.readouterr().out
