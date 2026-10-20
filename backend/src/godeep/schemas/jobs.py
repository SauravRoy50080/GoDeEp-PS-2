"""Versioned analysis-job contracts; only implemented adapters are accepted."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_validator

from godeep.schemas.intake import Record


class JobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sample_id: UUID
    adapter: Literal[
        "archive_inventory",
        "android_static",
        "dex_static",
        "dex_calls",
        "static_review",
        "signature_verify",
        "resource_inventory",
        "threat_review",
        "evasion_review",
    ] = "archive_inventory"


class JobRead(Record):
    case_id: UUID
    sample_id: UUID
    requested_by: UUID
    adapter: str
    adapter_version: str
    config: dict
    input_sha256: str
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    attempt: int
    parent_id: UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    result_sha256: str | None

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_times(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class JobResult(BaseModel):
    job_id: UUID
    adapter: str
    adapter_version: str
    input_sha256: str
    result_sha256: str
    data: dict
