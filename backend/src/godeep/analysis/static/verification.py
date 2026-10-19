"""Official apksigner verification; extraction and operational failures stay distinct."""

import hashlib
import os
import re

from godeep.workers.bounded_tool import run_tool


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def interpret_verification(run):
    if run["status"] != "exited":
        return run["status"], {}
    output = run["output"]
    if run["exit_code"] == 0 and output.splitlines()[:1] == ["Verifies"]:
        schemes = {}
        # Only read the initial fixed-format summary, before certificate-derived text.
        for line in output.splitlines()[1:]:
            match = re.fullmatch(
                r"Verified using (v[1-4](?:\.1)?) scheme \([^)]*\): (true|false)", line
            )
            if not match:
                break
            schemes[match[1]] = match[2] == "true"
        return "verified", schemes
    if run["exit_code"] == 1 and output.splitlines()[:1] == ["DOES NOT VERIFY"]:
        return "verification_failed", {}
    return "tool_error", {}


def verify_signature(snapshot, settings):
    result = {
        "status": "tool_unavailable",
        "cryptographic_verification": "not_performed",
        "scope": "Manifest minimum through verifier default maximum; no explicit SDK override",
        "input_sha256": file_hash(snapshot),
        "schemes": {},
        "limitations": [
            "Signature verification does not establish safety, reputation or installability",
            "No v4 sidecar is supplied; lineage details are not normalized",
            "Certificate extraction results remain separate from verified signer identities",
        ],
    }
    java, jar = settings.signer_java_path, settings.signer_jar_path
    if java is None or jar is None or settings.signer_jar_sha256 is None:
        result["reason"] = "operator_configuration_required"
        return result
    if (
        not java.is_absolute()
        or not jar.is_absolute()
        or java.suffix.lower() != ".exe"
        or jar.suffix.lower() != ".jar"
    ):
        result["reason"] = "invalid_operator_paths"
        return result
    if os.name != "nt":
        result["status"] = "unsupported_platform"
        return result
    try:
        if not java.is_file() or not jar.is_file():
            result["reason"] = "configured_tool_missing"
            return result
        jar_hash, java_hash = file_hash(jar), file_hash(java)
    except OSError:
        result["reason"] = "configured_tool_unreadable"
        return result
    result["tool"] = {
        "name": "apksigner",
        "jar_sha256": jar_hash,
        "java_executable_sha256": java_hash,
    }
    if jar_hash != settings.signer_jar_sha256:
        result["status"] = "provenance_mismatch"
        return result
    prefix = [
        str(java),
        "-Xmx256m",
        "-Dfile.encoding=UTF-8",
        "-Duser.language=en",
        "-Duser.country=US",
    ]
    for name, args in [
        ("java_version", prefix + ["-version"]),
        ("version", prefix + ["-jar", str(jar), "version"]),
    ]:
        probe = run_tool(
            args,
            snapshot.parent,
            min(5, settings.signer_timeout_seconds),
            settings.max_signer_output_bytes,
        )
        if probe["status"] != "exited" or probe["exit_code"] != 0:
            result["status"] = probe["status"] if probe["status"] != "exited" else "tool_error"
            result["diagnostic_output"] = probe["output"]
            return result
        result["tool"][name] = probe["output"].strip()
    run = run_tool(
        prefix + ["-jar", str(jar), "verify", "--verbose", "--print-certs", str(snapshot)],
        snapshot.parent,
        settings.signer_timeout_seconds,
        settings.max_signer_output_bytes,
    )
    result["status"], result["schemes"] = interpret_verification(run)
    result["exit_code"], result["diagnostic_output"] = run["exit_code"], run["output"]
    result["diagnostic_text_sha256"] = hashlib.sha256(run["output"].encode()).hexdigest()
    result["cryptographic_verification"] = (
        result["status"]
        if result["status"] in ("verified", "verification_failed")
        else "not_completed"
    )
    if file_hash(snapshot) != result["input_sha256"]:
        result["status"] = "input_changed_during_verification"
        result["cryptographic_verification"] = "not_completed"
        result["schemes"] = {}
    return result
