"""Manifest/component/permission and unverified signing-evidence adapter."""

from importlib.metadata import version
from pathlib import Path
from zipfile import ZipFile

from godeep.analysis.static.manifest import RULE_VERSION, parse_manifest
from godeep.analysis.static.signing import inspect_signing
from godeep.integrations.analyzers.common import prepare_snapshot, read_member

NAME = "android_static"
VERSION = "1.0.0"


def analyze(original: Path, snapshot: Path, expected_hash: str, config: dict):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    with ZipFile(snapshot) as archive:
        raw = read_member(
            archive, archive.getinfo("AndroidManifest.xml"), settings.max_manifest_bytes
        )
        manifest = parse_manifest(raw, settings)
        signing = inspect_signing(snapshot, archive, settings)
    return {
        "schema_version": 1,
        "adapter": NAME,
        "adapter_version": VERSION,
        "input_sha256": expected_hash,
        "input_size_bytes": size,
        "tool_versions": {name: version(name) for name in ["androguard", "cryptography", "lxml"]},
        "rule_version": RULE_VERSION,
        "manifest": manifest,
        "signing": signing,
        "coverage": {
            "manifest": "parsed_with_anomalies"
            if manifest["source"]["decoder_anomalies"]
            else "parsed",
            "signing": signing["coverage"],
            "dex_code": "not_analyzed",
            "dynamic": "not_analyzed",
            "resources": "not_resolved",
        },
        "limitations": [
            "Static manifest review leads are not confirmed vulnerabilities or malware",
            "No certificate/signature verification or malware probability is produced",
        ],
    }
