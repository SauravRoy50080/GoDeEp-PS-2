"""Strict operator-selected emulator profile, separate from HTTP request inputs."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SandboxProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False, strict=True)
    schema_version: Literal[1]
    adb_server_port: int = Field(default=5038, ge=1024, le=65535, strict=True)
    emulator_serial: str = Field(pattern=r"^emulator-[0-9]{4,5}$")
    avd_name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    api_level: int = Field(ge=24, le=999, strict=True)
    abi: Literal["x86_64", "arm64-v8a", "x86", "armeabi-v7a"]
    command_timeout_seconds: float = Field(default=2, ge=0.1, le=10)
    total_timeout_seconds: float = Field(default=15, ge=0.1, le=60)
    max_output_bytes: int = Field(default=16384, ge=64, le=65536, strict=True)

    @field_validator("adb_server_port")
    @classmethod
    def dedicated_port(cls, value):
        if value == 5037:
            raise ValueError("Use a dedicated non-default ADB server port")
        return value

    @field_validator("emulator_serial")
    @classmethod
    def emulator_port(cls, value):
        port = int(value.split("-")[1])
        if port < 5554 or port > 65534 or port % 2:
            raise ValueError("Expected an even emulator console port from 5554 through 65534")
        return value

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema(cls, value):
        if type(value) is not int:
            raise ValueError("Integer schema version required")
        return value
