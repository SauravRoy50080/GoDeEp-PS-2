"""Resource, embedded-file and declared-library inventory on a verified snapshot."""

from zipfile import ZipFile

from godeep.analysis.static.resources import inspect_resources
from godeep.integrations.analyzers.common import prepare_snapshot

NAME = "resource_inventory"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    settings, size = prepare_snapshot(original, snapshot, expected_hash, config)
    with ZipFile(snapshot) as archive:
        observations = inspect_resources(archive, settings)
    return {
        "schema_version": 1,
        "adapter": NAME,
        "adapter_version": VERSION,
        "rule_version": "1.0.0",
        "input_sha256": expected_hash,
        "input_size_bytes": size,
        "observations": observations,
        "coverage": observations["coverage"],
        "limitations": observations["limitations"],
    }
