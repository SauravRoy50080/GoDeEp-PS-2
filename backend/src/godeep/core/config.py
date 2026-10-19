"""Environment-based configuration; local data never belongs in Git."""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GODEEP_", env_file=BACKEND_ROOT / ".env", extra="ignore"
    )
    app_name: str = "GoDeEp API"
    environment: Literal["development", "test", "production"] = "development"
    database_url: SecretStr = SecretStr("postgresql+psycopg://godeep@127.0.0.1:5432/godeep")
    evidence_root: Path = BACKEND_ROOT / "data" / "evidence"
    max_upload_bytes: int = Field(default=200 * 1024 * 1024, ge=1)
    max_archive_entries: int = Field(default=10000, ge=1, le=65534)
    max_uncompressed_bytes: int = Field(default=1024 * 1024 * 1024, ge=1)
    max_central_directory_bytes: int = Field(default=8 * 1024 * 1024, ge=1)

    session_ttl_seconds: int = Field(default=28800, ge=60, le=86400)
    login_max_attempts: int = Field(default=5, ge=1, le=20)
    login_lock_seconds: int = Field(default=900, ge=60, le=86400)

    job_timeout_seconds: int = Field(default=60, ge=1, le=300)
    worker_poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    max_result_bytes: int = Field(default=1048576, ge=1024, le=10485760)
