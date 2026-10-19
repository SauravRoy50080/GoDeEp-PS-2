"""Shared original-byte verification and bounded private snapshots."""

import hashlib
from pathlib import Path

from godeep.analysis.static.archive import validate_archive
from godeep.core.config import Settings


class AdapterFailure(Exception):
    pass


def prepare_snapshot(original: Path, snapshot: Path, expected_hash: str, config: dict):
    settings = Settings(
        _env_file=None, **{k: v for k, v in config.items() if k in Settings.model_fields}
    )
    digest, size = hashlib.sha256(), 0
    with original.open("rb") as source, snapshot.open("xb") as destination:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise AdapterFailure("input_size_exceeded")
            digest.update(chunk)
            destination.write(chunk)
    if digest.hexdigest() != expected_hash:
        raise AdapterFailure("input_integrity_mismatch")
    validate_archive(snapshot, settings)
    return settings, size


def read_member(archive, member, limit: int) -> bytes:
    if member.file_size > limit:
        raise AdapterFailure("member_size_exceeded")
    with archive.open(member) as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise AdapterFailure("member_size_exceeded")
    return raw
