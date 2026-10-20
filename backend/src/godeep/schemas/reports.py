"""Explicit source selection and public report metadata; no internal storage paths."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from godeep.schemas.intake import Record


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_ids: list[UUID] = Field(min_length=1, max_length=20)

    @field_validator("job_ids")
    @classmethod
    def distinct_jobs(cls, value):
        if len(value) != len(set(value)):
            raise ValueError("Duplicate source jobs are not allowed")
        return value


class ReportRead(Record):
    case_id: UUID
    sample_id: UUID
    created_by: UUID
    source_job_ids: list[UUID]
    input_sha256: str
    artifact_sha256: str
    size_bytes: int
    schema_version: int
