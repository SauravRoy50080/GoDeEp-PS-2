"""Combined static/resource evidence with pinned offline intelligence matching."""

from zipfile import ZipFile

from godeep.analysis.correlation.intelligence import enrich
from godeep.analysis.static.resources import inspect_resources
from godeep.core.config import Settings
from godeep.integrations.analyzers.static_review import VERSION as STATIC_VERSION
from godeep.integrations.analyzers.static_review import analyze as static_analyze

NAME = "threat_review"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    result = static_analyze(original, snapshot, expected_hash, config)
    settings = Settings(
        _env_file=None, **{k: v for k, v in config.items() if k in Settings.model_fields}
    )
    with ZipFile(snapshot) as archive:
        resources = inspect_resources(archive, settings)
    candidates = [
        {
            "kind": "apk_sha256",
            "value": expected_hash,
            "evidence": {"kind": "original_apk", "sha256": expected_hash},
        }
    ]
    for member in result["dex"]["dex_files"]:
        for indicator in member.get("network_candidates", []):
            candidates.append(
                {
                    "kind": indicator["kind"],
                    "value": indicator["value"],
                    "evidence": {
                        "member": member["member"],
                        "sha256": member["sha256"],
                        **indicator,
                    },
                }
            )
    for indicator in resources["network_candidates"]:
        candidates.append(
            {"kind": indicator["kind"], "value": indicator["value"], "evidence": indicator}
        )
    for cert in result["signing"]["certificates"]:
        candidates.append(
            {
                "kind": "certificate_sha256",
                "value": cert["sha256"],
                "evidence": {
                    "kind": "extracted_unverified_certificate",
                    "sha256": cert["sha256"],
                    "sources": cert["sources"],
                },
            }
        )
    intelligence = enrich(candidates, settings)
    result.update(
        {
            "adapter": NAME,
            "adapter_version": VERSION,
            "resources": resources,
            "intelligence": intelligence,
        }
    )
    result["component_versions"].update(
        {
            "static_review": STATIC_VERSION,
            "resource_inventory": "1.0.0",
            "intelligence": intelligence["rule_version"],
        }
    )
    result["coverage"].update(
        {
            "resources": resources["coverage"],
            "resource_reference_resolution": "not_resolved",
            "intelligence": intelligence["coverage"],
        }
    )
    result["limitations"] += [
        "No external intelligence service is contacted",
        "Feed matching does not imply runtime contact or malware classification",
    ]
    return result
