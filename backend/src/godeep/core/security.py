"""Argon2id passwords and random, hash-at-rest bearer sessions."""

import hashlib
import secrets
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

# OWASP baseline: Argon2id, 19 MiB, two iterations, one degree of parallelism.
hasher = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1, type=Type.ID)
_dummy_hash = hasher.hash(secrets.token_urlsafe(32))


def verify_password(encoded: str | None, password: str) -> bool:
    try:
        valid = hasher.verify(encoded or _dummy_hash, password)
        return valid and encoded is not None
    except (VerificationError, InvalidHashError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
