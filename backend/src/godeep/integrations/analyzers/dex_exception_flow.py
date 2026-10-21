"""Explicit opt-in to bounded normal and conservative DEX exceptional flow."""

from godeep.analysis.static.control_flow import FlowParser
from godeep.core.config import Settings
from godeep.integrations.analyzers.dex_static import analyze_members

NAME = "dex_exception_flow"
VERSION = "1.0.0"


def analyze(original, snapshot, expected_hash, config):
    settings = Settings(
        _env_file=None,
        **{key: value for key, value in config.items() if key in Settings.model_fields},
    )
    parser = FlowParser(settings, exception_aware=True)
    result = analyze_members(
        original,
        snapshot,
        expected_hash,
        config,
        parser=parser,
        name=NAME,
        version=VERSION,
        complete="normal_and_exception_targets_checked",
        limitations=[
            "Conservative exception edges include every protected block, even nonthrowing opcodes",
            "Catch order is retained; type hierarchy, shadowing and dispatch are unresolved",
            "Checked ranges and targets do not prove feasible paths or runtime execution",
            "Try ranges containing payload data are rejected conservatively",
            "Unreferenced handler targets are checked, without adding edges",
            "Full map ownership, checksum and instruction/register/type verification are absent",
            "move-exception placement/register rules are unchecked; handler targets may omit it",
            "Normal edges into handlers are retained without Android verifier equivalence",
            "Native code, reflection, interprocedural dispatch and dynamic loading are unresolved",
            "Invalid or over-budget methods publish no graph; inspect decoder and flow issues",
            "Blocks and metadata IDs are local to one method and DEX member",
        ],
    )
    result["exception_flow_summary"] = {
        "attempted_methods": parser.attempted,
        "retained_methods": parser.retained,
        "retained_blocks": parser.blocks,
        "retained_edges": parser.edges,
        "retained_try_regions": parser.tries,
        "retained_handler_records": parser.handlers,
        "retained_typed_catches": parser.catches,
        "budgets": {
            "methods": settings.max_cfg_methods,
            "blocks": settings.max_cfg_blocks,
            "edges": settings.max_cfg_edges,
            "code_units_per_method": settings.max_cfg_code_units,
            "try_regions": settings.max_exception_tries,
            "handler_records": settings.max_exception_handlers,
            "typed_catches": settings.max_exception_catches,
            "table_bytes_per_method": settings.max_exception_table_bytes,
        },
    }
    return result
