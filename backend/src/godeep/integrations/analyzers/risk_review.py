"""One static/threat snapshot with explained, uncalibrated review prioritization."""

from godeep.analysis.correlation.risk import VERSION as POLICY_VERSION
from godeep.analysis.correlation.risk import prioritize
from godeep.integrations.analyzers.threat_review import VERSION as THREAT_VERSION
from godeep.integrations.analyzers.threat_review import analyze as threat_analyze

NAME = "risk_review"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    result = threat_analyze(original, snapshot, expected_hash, config)
    priority = prioritize(result)
    result.update({"adapter": NAME, "adapter_version": VERSION, "risk_review": priority})
    result["component_versions"].update(
        {"threat_review": THREAT_VERSION, "priority_policy": POLICY_VERSION}
    )
    result["coverage"]["risk_scoring"] = "uncalibrated_static_priority_policy"
    result["limitations"] += priority["limitations"]
    return result
