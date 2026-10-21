"""Bounded method-ID operand graphs; no dispatch, reachability or CFG claims."""

from godeep.analysis.static.calls import parse_calls


class GraphParser:
    """One instance per APK; graph budgets are shared across all DEX members."""

    def __init__(self, settings):
        self.remaining_edges = settings.max_graph_edges
        self.remaining_nodes = settings.max_graph_nodes
        self.nodes = 0
        self.edges = 0

    def __call__(self, raw, settings):
        # Internal zero budget still permits decoding but retains no further edges.
        bounded = settings.model_copy(update={"max_dex_findings": self.remaining_edges})
        parsed = parse_calls(raw, bounded, include_all_invokes=True)
        nodes, edges = {}, []
        limited = False
        for call in parsed["call_sites"]:
            caller, target = call["caller"], call["target"]
            caller_id = "method:" + str(caller["method_index"])
            target_id = "method:" + str(target["method_index"])
            required = {value for value in (caller_id, target_id) if value not in nodes}
            if len(nodes) + len(required) > self.remaining_nodes:
                limited = True
                continue
            nodes.setdefault(caller_id, {"id": caller_id, "method": caller, "roles": []})
            nodes.setdefault(target_id, {"id": target_id, "method": target, "roles": []})
            if "caller" not in nodes[caller_id]["roles"]:
                nodes[caller_id]["roles"].append("caller")
            if "target_operand" not in nodes[target_id]["roles"]:
                nodes[target_id]["roles"].append("target_operand")
            edges.append(
                {
                    "caller": caller_id,
                    "target": target_id,
                    "opcode": call["opcode"],
                    "byte_offset": call["byte_offset"],
                    "code_item_offset": call["code_item_offset"],
                    "instruction_offset_bytes": call["instruction_offset_bytes"],
                    "instruction_offset_code_units": call["instruction_offset_code_units"],
                    "sensitive_rule_id": call["rule_id"]
                    if call["rule_id"] != "DEX.INVOKE_OPERAND"
                    else None,
                    "evidence_state": "decoded_method_id_operand",
                }
            )
        self.remaining_edges -= len(edges)
        self.remaining_nodes -= len(nodes)
        self.nodes += len(nodes)
        self.edges += len(edges)
        partial = limited or parsed["coverage"] != "call_sites_decoded"
        return {
            "sha256": parsed["sha256"],
            "version": parsed["version"],
            "counts": parsed["counts"],
            "coverage": "partial" if partial else "graph_edges_extracted",
            "instruction_analysis": parsed["instruction_analysis"],
            "invoke_graph": {
                "nodes": [nodes[key] for key in sorted(nodes)],
                "edges": edges,
                "retained_nodes": len(nodes),
                "retained_edges": len(edges),
                "node_output_limited": limited,
                "decoder_output_limited": parsed["instruction_analysis"]["output_limited"],
                "coverage": "partial" if partial else "selected_linear_sweep_complete",
                "node_scope": "this_dex_member_only",
                "target_resolution": "method_id_operand_only",
                "virtual_dispatch": "not_resolved",
                "reachability": "not_analyzed",
                "runtime_execution": "not_observed",
                "control_flow_validation": "not_performed",
            },
        }
