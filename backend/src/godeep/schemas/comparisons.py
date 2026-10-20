"""Explicit same-case run selection; no implicit latest-run comparison."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator


class ComparisonCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    left_job_id: UUID
    right_job_id: UUID

    @model_validator(mode="after")
    def distinct_runs(self):
        if self.left_job_id == self.right_job_id:
            raise ValueError("Select two distinct analysis runs")
        return self
