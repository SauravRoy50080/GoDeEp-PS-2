"""Explicit capture selection and bounded filters for read-only runtime timelines."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class TimelineQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_ids: list[UUID] = Field(min_length=1, max_length=10)
    kinds: list[Literal["process", "filesystem", "network", "sensitive_access"]] = Field(
        default_factory=list, max_length=4
    )
    started_at: datetime | None = None
    ended_at: datetime | None = None
    limit: int = Field(default=100, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=20000)

    @field_validator("capture_ids", "kinds")
    @classmethod
    def distinct(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Duplicate selections are not allowed")
        return values

    @field_validator("started_at", "ended_at")
    @classmethod
    def aware(cls, value):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Timezone-aware filter required")
        return value

    @model_validator(mode="after")
    def interval(self):
        if self.started_at and self.ended_at and self.started_at > self.ended_at:
            raise ValueError("Start filter must not follow end filter")
        return self
