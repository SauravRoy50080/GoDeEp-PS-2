"""Instruction-site evidence adapter; retains identifier-only adapter compatibility."""

from godeep.analysis.static.calls import parse_calls
from godeep.integrations.analyzers.dex_static import analyze_members

NAME = "dex_calls"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    return analyze_members(
        original,
        snapshot,
        expected_hash,
        config,
        parser=parse_calls,
        name=NAME,
        version=VERSION,
        complete="call_sites_decoded",
        limitations=[
            "Decoded invoke instructions are not proof of execution or reachability",
            "Linear sweep does not validate control flow, try handlers or full DEX structure",
            "Polymorphic/custom invokes remain unresolved and produce partial coverage",
            "Reflection targets, virtual dispatch targets and cross-DEX call graphs are unresolved",
            "String network candidates do not prove observed traffic; no external requests made",
            "Malformed streams discard call-site findings from that method",
            "No malware verdict, risk score or Android installability verdict is produced",
        ],
    )
