"""Versioned static review of loading and evasion-related investigation leads."""

from zipfile import ZipFile

from godeep.analysis.correlation.evasion import VERSION as RULE_VERSION
from godeep.analysis.correlation.evasion import review
from godeep.analysis.static.resources import inspect_resources
from godeep.core.config import Settings
from godeep.integrations.analyzers.static_review import VERSION as STATIC_VERSION
from godeep.integrations.analyzers.static_review import analyze as static_analyze

NAME = "evasion_review"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    result = static_analyze(original, snapshot, expected_hash, config)
    settings = Settings(
        _env_file=None, **{k: v for k, v in config.items() if k in Settings.model_fields}
    )
    with ZipFile(snapshot) as archive:
        resources = inspect_resources(archive, settings)
    leads = review(result["dex"], resources, expected_hash, settings)
    result.update(
        {
            "adapter": NAME,
            "adapter_version": VERSION,
            "resources": resources,
            "evasion_review": leads,
        }
    )
    result["component_versions"].update(
        {
            "static_review": STATIC_VERSION,
            "resource_inventory": "1.0.0",
            "evasion_rules": RULE_VERSION,
        }
    )
    result["coverage"].update({"resources": resources["coverage"], "evasion": leads["coverage"]})
    result["limitations"] += leads["limitations"]
    return result
