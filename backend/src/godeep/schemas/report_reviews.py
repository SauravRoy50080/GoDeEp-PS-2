"""Analyst judgments are separate from recorded evidence and automated findings."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from godeep.schemas.intake import Record


class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_kind: Literal["analysis", "runtime_capture"]
    source_id: UUID
    pointer: str = Field(min_length=1, max_length=1024)

    @field_validator("pointer")
    @classmethod
    def storage_text(cls, value):
        if "\0" in value or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("Evidence pointers require Unicode scalar values without NUL")
        return value


class ReviewCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    supersedes_id: UUID | None = None
    decision: Literal["comment", "supported", "disputed", "follow_up"] = "comment"
    text: str = Field(min_length=1, max_length=4000)
    evidence_references: list[EvidenceReference] = Field(default_factory=list, max_length=10)

    @field_validator("text")
    @classmethod
    def meaningful(cls, value):
        if (
            not value.strip()
            or "\0" in value
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
        ):
            raise ValueError("Review text must not be blank")
        return value

    @model_validator(mode="after")
    def references(self):
        keys = {
            (item.source_kind, item.source_id, item.pointer) for item in self.evidence_references
        }
        if len(keys) != len(self.evidence_references):
            raise ValueError("Duplicate evidence reference")
        if self.decision != "comment" and not self.evidence_references:
            raise ValueError("Review decisions require evidence references")
        return self


class ReviewRead(Record):
    report_id: UUID
    thread_id: UUID
    supersedes_id: UUID | None
    created_by: UUID
    report_sha256: str
    decision: str
    text: str
    evidence_references: list[dict]
