"""Pinned operator-supplied Maven advisory claims; exact declared versions only."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    field_validator,
    model_validator,
)

from godeep.integrations.intelligence.local_feed import unique_keys

Coordinate = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,200}$")]
Version = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.+()-]{1,100}$")]


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,100}$")
    group_id: Coordinate
    artifact_id: Coordinate
    versions: list[Version] = Field(min_length=1, max_length=100)
    assertion: Literal["affected", "not_affected"]
    title: str = Field(min_length=1, max_length=300)
    reference: HttpUrl | None = None
    withdrawn: bool = Field(default=False, strict=True)
    valid_until: datetime | None = None

    @field_validator("versions")
    @classmethod
    def unique_versions(cls, values):
        if len(set(values)) != len(values):
            raise ValueError("Duplicate exact versions")
        return values

    @field_validator("valid_until")
    @classmethod
    def aware(cls, value):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("Timezone required")
        return value


class LibraryFeed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    feed_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    source_name: str = Field(min_length=1, max_length=200)
    published_at: datetime
    valid_until: datetime
    advisories: list[Advisory] = Field(max_length=5000)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema(cls, value):
        if type(value) is not int:
            raise ValueError("Integer schema required")
        return value

    @model_validator(mode="after")
    def consistent(self):
        if any(
            value.tzinfo is None or value.utcoffset() is None
            for value in (self.published_at, self.valid_until)
        ):
            raise ValueError("Timezone required")
        if self.valid_until <= self.published_at:
            raise ValueError("Invalid feed validity interval")
        if len({entry.id for entry in self.advisories}) != len(self.advisories):
            raise ValueError("Duplicate advisory IDs")
        if sum(len(entry.versions) for entry in self.advisories) > 50000:
            raise ValueError("Expanded version index exceeds bounds")
        return self


def load_library_feed(settings, now=None):
    now = now or datetime.now(UTC)
    metadata = {
        "status": "not_configured",
        "checked_at": now.isoformat(),
        "network_requests": 0,
        "index": {},
    }
    path, pinned = settings.library_feed_path, settings.library_feed_sha256
    if path is None and pinned is None:
        return metadata
    if path is None or pinned is None or not path.is_absolute():
        return {**metadata, "status": "invalid_configuration"}
    try:
        with path.open("rb") as source:
            raw = source.read(settings.max_library_feed_bytes + 1)
    except OSError:
        return {**metadata, "status": "feed_unavailable"}
    if len(raw) > settings.max_library_feed_bytes:
        return {**metadata, "status": "feed_size_limit"}
    digest = hashlib.sha256(raw).hexdigest()
    metadata["feed_sha256"] = digest
    if digest != pinned:
        return {**metadata, "status": "feed_hash_mismatch"}

    def invalid(value):
        raise ValueError("Non-finite JSON")

    try:
        feed = LibraryFeed.model_validate(
            json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid)
        )
    except (ValueError, UnicodeError, RecursionError):
        return {**metadata, "status": "feed_invalid"}
    metadata.update(
        {
            "feed_id": feed.feed_id,
            "source_name": feed.source_name,
            "published_at": feed.published_at.isoformat(),
            "valid_until": feed.valid_until.isoformat(),
            "record_count": len(feed.advisories),
        }
    )
    if feed.published_at > now:
        return {**metadata, "status": "feed_from_future"}
    if feed.valid_until <= now:
        return {**metadata, "status": "feed_expired"}
    if now - feed.published_at > timedelta(days=settings.library_feed_max_age_days):
        return {**metadata, "status": "feed_stale"}
    index = {}
    for entry in feed.advisories:
        for version in entry.versions:
            index.setdefault((entry.group_id, entry.artifact_id, version), []).append(entry)
    for entries in index.values():
        entries.sort(key=lambda entry: entry.id)
    return {**metadata, "status": "available", "index": index}


def main():
    import argparse
    from pathlib import Path

    from godeep.core.config import Settings

    parser = argparse.ArgumentParser(description="Validate a pinned local Maven advisory feed")
    parser.add_argument("feed", type=Path)
    args = parser.parse_args()
    try:
        with args.feed.open("rb") as source:
            raw = source.read(2097153)
    except OSError:
        parser.exit(2, "Library feed unavailable.\n")
    settings = Settings(
        _env_file=None,
        library_feed_path=args.feed.resolve(),
        library_feed_sha256=hashlib.sha256(raw).hexdigest(),
    )
    metadata = load_library_feed(settings)
    metadata.pop("index")
    print(json.dumps(metadata, sort_keys=True))
    return 0 if metadata["status"] == "available" else 2


if __name__ == "__main__":
    raise SystemExit(main())
