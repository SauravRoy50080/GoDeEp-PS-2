"""Case services authorize first; this helper bounds and verifies artifact bytes."""

import hashlib

from fastapi import HTTPException


def read_verified(root, key, digest, limit):
    try:
        if not isinstance(key, str) or not key or not isinstance(digest, str):
            raise ValueError("Missing artifact reference")
        resolved_root = root.resolve()
        path = (resolved_root / key).resolve()
        if not path.is_relative_to(resolved_root):
            raise ValueError("Artifact path outside storage")
        with path.open("rb") as source:
            raw = source.read(limit + 1)
        if len(raw) > limit or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Artifact integrity mismatch")
        return raw
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Artifact unavailable or integrity check failed") from exc
