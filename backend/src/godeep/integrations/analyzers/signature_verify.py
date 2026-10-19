"""Optional official Android signature verifier; never runs application code."""

from godeep.analysis.static.verification import verify_signature
from godeep.integrations.analyzers.common import prepare_snapshot

NAME = "signature_verify"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    verification = verify_signature(snapshot, settings)
    return {
        "schema_version": 1,
        "adapter": NAME,
        "adapter_version": VERSION,
        "input_sha256": expected_hash,
        "input_size_bytes": size,
        "signature_verification": verification,
        "coverage": "verified_in_tool_scope"
        if verification["status"] == "verified"
        else "verification_failed"
        if verification["status"] == "verification_failed"
        else "not_completed",
        "limitations": [
            "Read verifier status and diagnostics; completed job does not imply a valid signature",
            "Verification is independent of a malware or risk verdict",
        ],
    }
