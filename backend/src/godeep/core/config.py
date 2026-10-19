"""Environment-based application configuration."""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GODEEP_", env_file=BACKEND_ROOT / ".env", extra="ignore"
    )

    app_name: str = "GoDeEp API"
    environment: Literal["development", "test", "production"] = "development"
