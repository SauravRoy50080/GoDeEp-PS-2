"""Per-member invoke operand graphs from one hash-verified APK snapshot."""

from godeep.analysis.static.graph import GraphParser
from godeep.core.config import Settings
from godeep.integrations.analyzers.dex_static import analyze_members

NAME = "dex_graph"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    settings = Settings(
        _env_file=None,
        **{key: value for key, value in config.items() if key in Settings.model_fields},
    )
    parser = GraphParser(settings)
    result = analyze_members(
        original,
        snapshot,
        expected_hash,
        config,
        parser=parser,
        name=NAME,
        version=VERSION,
        complete="graph_edges_extracted",
        limitations=[
            "Edges describe decoded method-ID operands, not verified runtime targets or execution",
            "Linear sweep does not validate branches, exception handlers or full DEX semantics",
            "Dispatch, reflection and custom/polymorphic invokes remain unresolved",
            "Node IDs are scoped to each DEX member; cross-DEX identities are not merged",
            "Only methods participating in retained invokes appear as graph nodes",
            "Graph budgets apply across all DEX files; omitted edges are not absence of behaviour",
            "No entrypoint reachability, data flow, malware verdict or risk score is inferred",
            "Overall worker byte/time limits still apply and can reject oversized graph results",
        ],
    )
    result["graph_summary"] = {
        "retained_nodes": parser.nodes,
        "retained_edges": parser.edges,
        "edge_budget": settings.max_graph_edges,
        "node_budget": settings.max_graph_nodes,
        "cross_dex_linking": "not_performed",
    }
    return result
