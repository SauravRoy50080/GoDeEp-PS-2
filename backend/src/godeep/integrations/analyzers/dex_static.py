"""Versioned multi-DEX identifier and network candidate adapter."""

import hashlib
import re
from zipfile import ZipFile

from godeep.analysis.static.dex import parse_dex
from godeep.integrations.analyzers.common import AdapterFailure, prepare_snapshot, read_member

NAME = "dex_static"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    return analyze_members(original, snapshot, expected_hash, config)


def analyze_members(
    original,
    snapshot,
    expected_hash,
    config,
    *,
    parser=parse_dex,
    name=NAME,
    version=VERSION,
    complete="identifier_tables_parsed",
    limitations=None,
):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    results, total = [], 0
    with ZipFile(snapshot) as archive:
        members = [
            m
            for m in archive.infolist()
            if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", m.filename)
        ]
        if len(members) > settings.max_dex_files:
            raise AdapterFailure("dex_limits_exceeded")
        for member in members:
            total += member.file_size
            if total > settings.max_dex_total_bytes:
                raise AdapterFailure("dex_limits_exceeded")
            raw = read_member(archive, member, settings.max_dex_bytes)
            try:
                data = parser(raw, settings)
            except AdapterFailure as exc:
                data = {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "coverage": "failed",
                    "error_code": str(exc),
                }
            results.append({"member": member.filename, **data})
    partial = any(d["coverage"] != complete for d in results)
    return {
        "schema_version": 1,
        "adapter": name,
        "adapter_version": version,
        "rule_version": "1.0.0",
        "input_sha256": expected_hash,
        "input_size_bytes": size,
        "dex_files": results,
        "coverage": "no_dex_found" if not results else "partial" if partial else complete,
        "limitations": limitations
        or [
            "Identifier references do not prove invocation, reachability or maliciousness",
            "Network candidates are strings, not observed destinations; no external requests made",
            "Instructions, call graphs, obfuscation and anti-emulation are not analyzed",
            "Embedded payloads, native code, resources and encrypted strings are not analyzed",
            "DEX checksums, signatures and full structural validation are not performed",
            "Unsupported or malformed DEX files remain visible as failed coverage",
        ],
    }
