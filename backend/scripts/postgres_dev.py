"""Manage the configured portable development server without printing credentials."""

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Manage local PostgreSQL development server")
    parser.add_argument("action", choices=["start", "stop", "status"])
    action = parser.parse_args().action
    data = Path(__file__).resolve().parents[1] / "data"
    try:
        config = json.loads((data / "postgresql-admin.json").read_text(encoding="utf-8"))
        cluster = Path(config["cluster"])
        binary = Path(config["binary_directory"])
        port = int(config["port"])
        if not cluster.is_absolute() or not binary.is_absolute():
            raise ValueError("Absolute local paths required")
        if not (cluster / "PG_VERSION").is_file() or not (binary / "pg_ctl.exe").is_file():
            raise ValueError("Local runtime unavailable")
    except (OSError, ValueError, KeyError):
        print("Local portable PostgreSQL configuration/runtime is unavailable.")
        return 1
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    command = [str(binary / "pg_ctl.exe"), "-D", str(cluster)]
    check = subprocess.run(
        command + ["status"], capture_output=True, timeout=10, creationflags=flags
    )
    if action == "status":
        print(
            "Development PostgreSQL is running."
            if check.returncode == 0
            else "Development PostgreSQL is stopped."
        )
        return 0 if check.returncode == 0 else 1
    if action == "stop":
        result = subprocess.run(
            command + ["-m", "fast", "-w", "-t", "20", "stop"],
            capture_output=True,
            timeout=30,
            creationflags=flags,
        )
        print(
            "Development PostgreSQL stopped."
            if result.returncode == 0
            else "Unable to stop the development server."
        )
        return 0 if result.returncode == 0 else 1
    if check.returncode == 0:
        print("Development PostgreSQL is already running on port " + str(port) + ".")
        return 0
    with (data / "postgresql-dev.log").open("ab") as log:
        server = subprocess.Popen(
            [
                str(binary / "postgres.exe"),
                "-D",
                str(cluster),
                "-h",
                "127.0.0.1",
                "-p",
                str(port),
                "-c",
                "max_connections=40",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
    for _ in range(100):
        if server.poll() is not None:
            print("Server exited; inspect backend/data/postgresql-dev.log privately.")
            return 1
        probe = subprocess.run(
            command + ["status"], capture_output=True, timeout=5, creationflags=flags
        )
        if probe.returncode == 0:
            print("Development PostgreSQL started on port " + str(port) + ".")
            return 0
        time.sleep(0.1)
    print("Startup not confirmed; inspect backend/data/postgresql-dev.log privately.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
