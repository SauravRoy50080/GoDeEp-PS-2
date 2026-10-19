"""Public intake contracts. Storage paths and database credentials stay private."""

from datetime import UTC, datetime
from typing import Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CaseCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)


class Record(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        # SQLite loses tzinfo; PostgreSQL preserves timezone-aware timestamps.
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class CaseRead(Record):
    name: str
    description: str


class SampleRead(Record):
    case_id: UUID
    original_name: str
    sha256: str
    size_bytes: int
    intake_status: Literal["structure_checked"]


class AuditRead(Record):
    case_id: UUID
    action: str
    actor: str
    subject_id: UUID
    details: dict


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int
