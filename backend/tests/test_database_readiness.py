"""Readiness distinguishes database reachability from managed PID visibility."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import SQLAlchemyError

from godeep.core.config import Settings
from godeep.persistence.readiness import database_reachable


def test_probe_refuses_other_hosts_ports_and_backends(monkeypatch):
    def fail(url):
        raise AssertionError("Unexpected connection")

    monkeypatch.setattr("godeep.persistence.readiness.build_engine", fail)
    for url in (
        "postgresql+psycopg://u@remote:55433/db",
        "postgresql+psycopg://u@127.0.0.1:5432/db",
        "sqlite://",
    ):
        assert not database_reachable(55433, Settings(_env_file=None, database_url=url))


@pytest.mark.parametrize("failed", [False, True])
def test_probe_checks_connectivity_and_disposes_engine(monkeypatch, failed):
    class Engine:
        disposed = False

        def connect(self):
            if failed:
                raise SQLAlchemyError("private connection failure")
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def scalar(self, query):
            return 1

        def dispose(self):
            self.disposed = True

    engine = Engine()
    monkeypatch.setattr("godeep.persistence.readiness.build_engine", lambda url: engine)
    assert database_reachable(
        55433, Settings(_env_file=None, database_url="postgresql+psycopg://u@127.0.0.1:55433/db")
    ) is (not failed)
    assert engine.disposed


@pytest.mark.parametrize("action,expected", [("start", 0), ("status", 0), ("stop", 1)])
def test_reachable_unmanaged_database_never_restarted_or_stopped(
    tmp_path, monkeypatch, action, expected
):
    script = Path(__file__).resolve().parents[1] / "scripts/postgres_dev.py"
    spec = importlib.util.spec_from_file_location("postgres_dev_test", script)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    fake = tmp_path / "scripts/postgres_dev.py"
    fake.parent.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    cluster, binary = tmp_path / "cluster", tmp_path / "bin"
    cluster.mkdir()
    binary.mkdir()
    (cluster / "PG_VERSION").write_text("17")
    (binary / "pg_ctl.exe").write_text("fixture")
    (data / "postgresql-admin.json").write_text(
        json.dumps({"cluster": str(cluster), "binary_directory": str(binary), "port": 55433})
    )
    monkeypatch.setattr(helper, "__file__", str(fake))
    monkeypatch.setattr(helper, "database_reachable", lambda port: True)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert command[-1] == "status"  # A stop/start command would be an ownership error.
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(helper.subprocess, "run", run)
    monkeypatch.setattr("sys.argv", [str(fake), action])
    assert helper.main() == expected
    assert len(calls) == 1
