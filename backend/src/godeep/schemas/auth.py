"""Authentication contracts; passwords are never echoed in responses."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    password: SecretStr = Field(min_length=1, max_length=128)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    username: str


class TokenRead(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: datetime


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    token_digest: str


class MemberWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UUID
    role: Literal["analyst", "viewer"]


class MemberRead(MemberWrite):
    model_config = ConfigDict(from_attributes=True)
