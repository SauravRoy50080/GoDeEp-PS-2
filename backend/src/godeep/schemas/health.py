"""Liveness API response."""

from typing import Literal

from pydantic import BaseModel


class LivenessResponse(BaseModel):
    status: Literal["ok"] = "ok"
