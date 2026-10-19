"""One verified snapshot for manifest, signing, DEX invokes and unified review."""

from importlib.metadata import version
from zipfile import ZipFile

from godeep.analysis.correlation.review import correlate
from godeep.analysis.static.calls import parse_calls
from godeep.analysis.static.manifest import RULE_VERSION, parse_manifest
from godeep.analysis.static.signing import inspect_signing
from godeep.integrations.analyzers.common import AdapterFailure, prepare_snapshot, read_member
from godeep.integrations.analyzers.dex_calls import VERSION as CALLS_VERSION
from godeep.integrations.analyzers.dex_static import analyze_snapshot

NAME = "static_review"
VERSION = "1.0.1"


def analyze(original, snapshot, expected_hash, config):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    manifest = None
    with ZipFile(snapshot) as archive:
        try:
            raw = read_member(
                archive, archive.getinfo("AndroidManifest.xml"), settings.max_manifest_bytes
            )
            manifest = parse_manifest(raw, settings)
            manifest_phase = {
                "status": "parsed_with_anomalies"
                if manifest["source"]["decoder_anomalies"]
                else "parsed"
            }
        except AdapterFailure as exc:
            manifest_phase = {"status": "failed", "error_code": str(exc)}
        signing = inspect_signing(snapshot, archive, settings)
    try:
        dex = analyze_snapshot(
            snapshot,
            settings,
            size,
            expected_hash,
            parser=parse_calls,
            name="dex_calls",
            version=CALLS_VERSION,
            complete="call_sites_decoded",
            limitations=[
                "Decoded calls do not establish reachability or runtime execution",
                "Call graphs, dispatch resolution and full DEX validation are not performed",
            ],
        )
    except AdapterFailure as exc:
        dex = {"coverage": "failed", "error_code": str(exc), "dex_files": []}
    review = correlate(manifest, dex, expected_hash, settings)
    return {
        "schema_version": 1,
        "adapter": NAME,
        "adapter_version": VERSION,
        "input_sha256": expected_hash,
        "input_size_bytes": size,
        "tool_versions": {name: version(name) for name in ("androguard", "cryptography", "lxml")},
        "component_versions": {
            "manifest_rules": RULE_VERSION,
            "dex_calls": CALLS_VERSION,
            "correlation_rules": review["rule_version"],
        },
        "manifest": manifest,
        "signing": signing,
        "dex": dex,
        "review": review,
        "coverage": {
            "manifest": manifest_phase,
            "signing": signing["coverage"],
            "dex": dex["coverage"],
            "correlation": review["coverage"],
            "resources": "not_resolved",
            "dynamic": "not_analyzed",
            "intelligence": "not_queried",
            "risk_scoring": "not_implemented",
        },
        "limitations": [
            "Unified static review is not a complete malware assessment",
            "Consult every phase coverage field; an empty finding list is not a clean verdict",
            "Certificate metadata extraction does not verify APK signatures",
        ],
    }
