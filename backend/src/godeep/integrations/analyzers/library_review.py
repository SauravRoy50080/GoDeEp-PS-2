"""Resource declarations with pinned offline exact-version advisory matching."""

from godeep.analysis.correlation.libraries import review_libraries
from godeep.core.config import Settings
from godeep.integrations.analyzers.resource_inventory import analyze as inventory

NAME = "library_review"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    result = inventory(original, snapshot, expected_hash, config)
    settings = Settings(
        _env_file=None,
        **{key: value for key, value in config.items() if key in Settings.model_fields},
    )
    review = review_libraries(result["observations"], settings)
    for candidate in result["observations"]["library_candidates"]:
        candidate["vulnerability_status"] = "see_library_review"
    result.update(
        {
            "adapter": NAME,
            "adapter_version": VERSION,
            "library_review": review,
            "coverage": {
                "resources": result["observations"]["coverage"],
                "advisories": review["coverage"],
                "dynamic": "not_analyzed",
            },
            "component_versions": {
                "resource_inventory": "1.0.0",
                "library_rules": review["rule_version"],
            },
        }
    )
    result["limitations"] += review["limitations"]
    return result
