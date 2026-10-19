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
