"""Shared verification of stored collector traces before investigation use."""

from fastapi import HTTPException

from godeep.schemas.runtime_captures import decode_trace
from godeep.storage.artifacts import read_verified


def read_trace(root, capture, sample_sha256, limit):
    raw = read_verified(root, capture.artifact_key, capture.artifact_sha256, limit)
    if len(raw) != capture.size_bytes or capture.input_sha256 != sample_sha256:
        raise HTTPException(409, "Runtime capture metadata does not match source")
    try:
        trace = decode_trace(raw)
        if trace.input_sha256 != sample_sha256 or trace.source_run_id != capture.source_run_id:
            raise ValueError("Capture identity mismatch")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise HTTPException(409, "Source runtime trace is invalid") from exc
    return raw, trace
