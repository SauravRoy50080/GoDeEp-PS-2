"""Bounded collector observations; capture provenance is asserted, not verified."""

import json
from datetime import datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from godeep.schemas.intake import Record


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Event(StrictRecord):
    event_id: UUID
    timestamp: datetime
    pid: int = Field(ge=1, le=2147483647, strict=True)

    @field_validator("timestamp")
    @classmethod
    def timezone(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timezone-aware timestamp required")
        return value


class ProcessEvent(Event):
    kind: Literal["process"]
    action: Literal["start", "stop", "observed"]
    name: str = Field(min_length=1, max_length=200)


class FileEvent(Event):
    kind: Literal["filesystem"]
    operation: Literal["create", "read", "write", "delete"]
    path: str = Field(min_length=1, max_length=1024)
    content_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class NetworkEvent(Event):
    kind: Literal["network"]
    transport: Literal["tcp", "udp"]
    destination_ip: IPvAnyAddress
    destination_port: int = Field(ge=1, le=65535, strict=True)


class SensitiveEvent(Event):
    kind: Literal["sensitive_access"]
    resource: Literal["camera", "microphone", "location", "contacts", "sms"]
    operation: str = Field(min_length=1, max_length=80)


class Collector(StrictRecord):
    name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=80)


class Coverage(StrictRecord):
    process: Literal["collected", "partial", "not_collected"]
    filesystem: Literal["collected", "partial", "not_collected"]
    network: Literal["collected", "partial", "not_collected"]
    sensitive_access: Literal["collected", "partial", "not_collected"]


class RuntimeTrace(StrictRecord):
    schema_version: Literal[1]
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_run_id: str = Field(min_length=1, max_length=200)
    collector: Collector
    environment: Literal["emulator", "physical_device", "external_sandbox"]
    package_name: str = Field(
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$", max_length=255
    )
    started_at: datetime
    ended_at: datetime
    collection_status: Literal["completed", "partial", "failed"]
    coverage: Coverage
    events: list[
        Annotated[
            ProcessEvent | FileEvent | NetworkEvent | SensitiveEvent, Field(discriminator="kind")
        ]
    ] = Field(max_length=2000)

    @model_validator(mode="after")
    def consistent(self):
        for value in (self.started_at, self.ended_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Timezone-aware collection timestamps required")
        if not timedelta(0) <= self.ended_at - self.started_at <= timedelta(days=1):
            raise ValueError("Collection interval must be between zero and 24 hours")
        previous, seen = self.started_at, set()
        for event in self.events:
            if event.event_id in seen or not previous <= event.timestamp <= self.ended_at:
                raise ValueError("Events must have unique IDs and ordered in-range times")
            if getattr(self.coverage, event.kind) == "not_collected":
                raise ValueError("Event contradicts source coverage")
            previous = event.timestamp
            seen.add(event.event_id)
        return self


class CaptureRead(Record):
    case_id: UUID
    sample_id: UUID
    created_by: UUID
    input_sha256: str
    artifact_sha256: str
    size_bytes: int
    source_run_id: str
    summary: dict


def decode_trace(raw):
    """Strict JSON plus structural and semantic validation, shared by imports/reports."""

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    def invalid(value):
        raise ValueError("Non-finite JSON")

    data = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
        raise ValueError("Invalid schema")
    return RuntimeTrace.model_validate(data)
