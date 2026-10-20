"""Validated, pinned local intelligence feed. Never makes a network request."""

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

KINDS = Literal["domain", "ip", "url", "apk_sha256", "certificate_sha256"]


def canonical(kind, value):
    value = value.strip()
    if len(value) > 2048:
        raise ValueError("Indicator too long")
    if kind in ("apk_sha256", "certificate_sha256"):
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            raise ValueError("Invalid SHA-256")
        return value.lower()
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind == "domain":
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
        if not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host
        ):
            raise ValueError("Invalid domain")
        return host
    if kind == "url":
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Userinfo URLs are unsupported")
        if any(ord(char) <= 32 for char in value):
            raise ValueError("Invalid URL characters")
        try:
            host = str(ipaddress.ip_address(parsed.hostname))
            host = "[" + host + "]" if ":" in host else host
        except ValueError:
            host = canonical("domain", parsed.hostname)
        if parsed.port is not None:
            host += ":" + str(parsed.port)
        return urlunsplit((parsed.scheme.lower(), host, parsed.path, parsed.query, parsed.fragment))
    raise ValueError("Unsupported indicator kind")


def aware(value):
    if value is not None and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError("Timezone-aware timestamps required")
    return value.astimezone(UTC) if value is not None else None


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)
    id: str = Field(min_length=1, max_length=100)
    kind: KINDS
    value: str = Field(min_length=1, max_length=2048)
    classification: Literal["malicious", "suspicious", "benign", "unknown"]
    confidence: Literal["low", "medium", "high", "unknown"]
    observed_at: datetime
    valid_until: datetime | None = None
    reference: str | None = Field(default=None, max_length=2048)

    _aware = field_validator("observed_at", "valid_until")(aware)

    @model_validator(mode="after")
    def validate_record(self):
        canonical(self.kind, self.value)
        if self.valid_until is not None and self.valid_until <= self.observed_at:
            raise ValueError("Indicator expiry must follow observation")
        if self.reference is not None:
            canonical("url", self.reference)
        return self


class Feed(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    feed_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,80}$")
    source_name: str = Field(min_length=1, max_length=200)
    source_url: str | None = Field(default=None, max_length=2048)
    published_at: datetime
    valid_until: datetime
    indicators: list[Indicator] = Field(max_length=10000)

    _aware = field_validator("published_at", "valid_until")(aware)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema_version(cls, value):
        if type(value) is not int:
            raise ValueError("Schema version must be an integer")
        return value

    @model_validator(mode="after")
    def validate_feed(self):
        if self.valid_until <= self.published_at:
            raise ValueError("Feed expiry must follow publication")
        if self.source_url is not None:
            canonical("url", self.source_url)
        if len({record.id for record in self.indicators}) != len(self.indicators):
            raise ValueError("Duplicate record IDs")
        if any(record.observed_at > self.published_at for record in self.indicators):
            raise ValueError("Observation cannot follow feed publication")
        return self


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def load_feed(settings, now=None):
    now = now or datetime.now(UTC)
    metadata = {
        "status": "not_configured",
        "checked_at": now.isoformat(),
        "network_requests": 0,
        "index": {},
    }
    path = settings.intel_feed_path
    if path is None or settings.intel_feed_sha256 is None:
        return metadata
    if not path.is_absolute():
        return {**metadata, "status": "invalid_configuration"}
    try:
        with path.open("rb") as source:
            raw = source.read(settings.max_intel_feed_bytes + 1)
    except OSError:
        return {**metadata, "status": "feed_unavailable"}
    if len(raw) > settings.max_intel_feed_bytes:
        return {**metadata, "status": "feed_size_limit"}
    digest = hashlib.sha256(raw).hexdigest()
    metadata["feed_sha256"] = digest
    if digest != settings.intel_feed_sha256:
        return {**metadata, "status": "feed_hash_mismatch"}
    try:
        feed = Feed.model_validate(json.loads(raw, object_pairs_hook=unique_keys))
    except (ValidationError, ValueError, UnicodeError, RecursionError):
        return {**metadata, "status": "feed_invalid"}
    metadata.update(
        {
            "feed_id": feed.feed_id,
            "source_name": feed.source_name,
            "source_url": feed.source_url,
            "published_at": feed.published_at.isoformat(),
            "valid_until": feed.valid_until.isoformat(),
            "record_count": len(feed.indicators),
        }
    )
    if feed.published_at > now:
        return {**metadata, "status": "feed_from_future"}
    if feed.valid_until <= now:
        return {**metadata, "status": "feed_expired"}
    if now - feed.published_at > timedelta(days=settings.intel_max_feed_age_days):
        return {**metadata, "status": "feed_stale"}
    index = {}
    for record in feed.indicators:
        index.setdefault((record.kind, canonical(record.kind, record.value)), []).append(record)
    return {**metadata, "status": "available", "index": index}


def main():
    import argparse
    from pathlib import Path

    from godeep.core.config import Settings

    parser = argparse.ArgumentParser(description="Validate a local GoDeEp intelligence feed")
    parser.add_argument("feed", type=Path)
    args = parser.parse_args()
    path = args.feed.resolve()
    settings = Settings(_env_file=None)
    try:
        with path.open("rb") as source:
            raw = source.read(settings.max_intel_feed_bytes + 1)
    except OSError:
        print(json.dumps({"status": "feed_unavailable"}))
        return 1
    if len(raw) > settings.max_intel_feed_bytes:
        print(json.dumps({"status": "feed_size_limit"}))
        return 1
    settings.intel_feed_path = path
    settings.intel_feed_sha256 = hashlib.sha256(raw).hexdigest()
    metadata = load_feed(settings)
    metadata.pop("index")
    print(json.dumps(metadata, sort_keys=True))
    return 0 if metadata["status"] == "available" else 1


if __name__ == "__main__":
    raise SystemExit(main())
