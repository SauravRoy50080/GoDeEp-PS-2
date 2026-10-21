"""Hash-verified multi-DEX intraprocedural normal-flow extraction."""

from godeep.analysis.static.control_flow import FlowParser
from godeep.core.config import Settings
from godeep.integrations.analyzers.dex_static import analyze_members

NAME = "dex_control_flow"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    settings = Settings(
        _env_file=None,
        **{key: value for key, value in config.items() if key in Settings.model_fields},
    )
    parser = FlowParser(settings)
    result = analyze_members(
        original,
        snapshot,
        expected_hash,
        config,
        parser=parser,
        name=NAME,
        version=VERSION,
        complete="normal_targets_checked",
        limitations=[
            "Syntactic normal edges do not establish execution, feasible paths or malicious intent",
            "Try structures/handlers are not validated; exceptional edges are not modeled",
            "Methods with try regions have partial coverage even when normal targets are checked",
            "Register/type checks, Android entrypoints and full DEX validation are not performed",
            "Blocks are method/DEX-local; interprocedural and cross-DEX flow are not inferred",
            "Disconnected instructions are retained; entry reachability is not computed",
            "Invalid or over-budget methods publish no graph; inspect every issue and limit",
            "Native code, reflection, dynamic loading and encrypted payloads are not resolved",
            "Worker time/byte limits can still reject oversized results",
        ],
    )
    result["normal_flow_summary"] = {
        "attempted_methods": parser.attempted,
        "retained_methods": parser.retained,
        "retained_blocks": parser.blocks,
        "retained_edges": parser.edges,
        "budgets": {
            "methods": settings.max_cfg_methods,
            "blocks": settings.max_cfg_blocks,
            "edges": settings.max_cfg_edges,
            "code_units_per_method": settings.max_cfg_code_units,
        },
    }
    return result
