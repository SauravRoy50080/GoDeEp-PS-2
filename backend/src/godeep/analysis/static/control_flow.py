"""Bounded syntactic intraprocedural normal flow; never an Android verifier."""

import struct

from androguard.core.dex import DALVIK_OPCODES_FORMAT

from godeep.analysis.static.calls import parse_calls


class InvalidFlow(Exception):
    pass


def build_method(
    raw, caller, code_offset, start, units, tries, registers, block_budget, edge_budget
):
    if block_budget < 1:
        raise InvalidFlow("cfg_output_budget")

    def number(fmt, unit):
        size = struct.calcsize(fmt)
        if unit < 0 or unit * 2 + size > units * 2:
            raise InvalidFlow("cfg_operand_bounds")
        return struct.unpack_from(fmt, raw, start + unit * 2)[0]

    instructions, payloads = {}, {}
    pos = 0
    while pos < units:
        word = number("<H", pos)
        op = word & 255
        if op == 0 and word:
            count = number("<H", pos + 1)
            if word == 0x100:
                width = 4 + count * 2
            elif word == 0x200:
                width = 2 + count * 4
            elif word == 0x300:
                width = 4 + (count * number("<I", pos + 2) + 1) // 2
            else:
                raise InvalidFlow("cfg_payload_kind_invalid")
            payloads[pos] = (word, count)
        else:
            entry = DALVIK_OPCODES_FORMAT[op]
            width = entry[0].length // 2
            instructions[pos] = {"opcode": op, "end": pos + width, "name": entry[1][0]}
        if width <= 0 or pos + width > units:
            raise InvalidFlow("cfg_instruction_bounds")
        pos += width
    if 0 not in instructions:
        raise InvalidFlow("cfg_entry_not_instruction")
    leaders, successors = {0}, {}
    previous_end = None
    branch_edges = 0
    for pos, instruction in instructions.items():
        if previous_end is not None and previous_end != pos:
            leaders.add(pos)  # Do not join code across data payloads.
        op, following = instruction["opcode"], instruction["end"]
        previous_end = following
        targets = []
        terminal = op in (0x0E, 0x0F, 0x10, 0x11, 0x27)
        branch = op in (0x28, 0x29, 0x2A, 0x2B, 0x2C) or 0x32 <= op <= 0x3D
        if op in (0x28, 0x29, 0x2A):
            if op == 0x28:
                delta = struct.unpack_from("<b", raw, start + pos * 2 + 1)[0]
            else:
                delta = number("<h" if op == 0x29 else "<i", pos + 1)
            if delta == 0 and op != 0x2A:
                raise InvalidFlow("cfg_zero_branch_offset")
            targets.append((pos + delta, "goto", None))
        elif 0x32 <= op <= 0x3D:
            word = number("<H", pos)
            operands = [(word >> 8) & 15, word >> 12] if op <= 0x37 else [word >> 8]
            if any(value >= registers for value in operands):
                raise InvalidFlow("cfg_branch_register_invalid")
            delta = number("<h", pos + 1)
            if delta == 0:
                raise InvalidFlow("cfg_zero_branch_offset")
            targets.extend([(pos + delta, "branch_taken", None), (following, "fallthrough", None)])
        elif op in (0x2B, 0x2C, 0x26):
            if number("<H", pos) >> 8 >= registers:
                raise InvalidFlow("cfg_branch_register_invalid")
            payload = pos + number("<i", pos + 1)
            expected = {0x2B: 0x100, 0x2C: 0x200, 0x26: 0x300}[op]
            if payload not in payloads or payloads[payload][0] != expected:
                raise InvalidFlow("cfg_payload_reference_invalid")
            count = payloads[payload][1]
            if op != 0x26:
                # Bound expansion even if many switches share a large payload.
                if branch_edges + count + 1 > edge_budget:
                    raise InvalidFlow("cfg_output_budget")
                first = number("<i", payload + 2) if op == 0x2B else None
                previous_key = None
                for index in range(count):
                    key = first + index if op == 0x2B else number("<i", payload + 2 + index * 2)
                    if key > 2147483647 or (previous_key is not None and key <= previous_key):
                        raise InvalidFlow("cfg_switch_keys_invalid")
                    previous_key = key
                    target_base = payload + (4 if op == 0x2B else 2 + count * 2)
                    delta = number("<i", target_base + index * 2)
                    targets.append((pos + delta, "switch_case", key))
            targets.append((following, "fallthrough", None))
        elif not terminal:
            targets.append((following, "fallthrough", None))
        if branch:
            branch_edges += len(targets)
            if branch_edges > edge_budget:
                raise InvalidFlow("cfg_output_budget")
        for target, _, _ in targets:
            if target not in instructions:
                raise InvalidFlow("cfg_target_not_instruction")
            if branch:
                leaders.add(target)
        if (branch or terminal) and following in instructions:
            leaders.add(following)  # Retain disconnected code without reachability claims.
        successors[pos] = targets

    blocks, owners = [], {}
    for pos, instruction in instructions.items():
        if pos in leaders or not blocks:
            if len(blocks) >= block_budget:
                raise InvalidFlow("cfg_output_budget")
            blocks.append(
                {
                    "id": f"block:{pos}",
                    "start_code_unit": pos,
                    "byte_offset": start + pos * 2,
                    "instruction_count": 0,
                }
            )
        block = blocks[-1]
        block["instruction_count"] += 1
        block["end_code_unit_exclusive"] = instruction["end"]
        block["terminal_code_unit"] = pos
        block["terminal_opcode"] = instruction["name"]
        owners[pos] = block["id"]
    edges = []
    for block in blocks:
        pos = block["terminal_code_unit"]
        for target, kind, key in successors[pos]:
            if len(edges) >= edge_budget:
                raise InvalidFlow("cfg_output_budget")
            edge = {
                "source": block["id"],
                "target": owners[target],
                "kind": kind,
                "instruction_code_unit": pos,
                "byte_offset": start + pos * 2,
            }
            if key is not None:
                edge["case_value"] = key
            edges.append(edge)
    return {
        "method": caller,
        "code_item_offset": code_offset,
        "instruction_start_byte": start,
        "code_units": units,
        "entry_block": "block:0",
        "blocks": blocks,
        "edges": edges,
        "payload_count": len(payloads),
        "try_region_count": tries,
        "coverage": "partial_exception_flow_unmodeled" if tries else "normal_targets_checked",
        "exception_flow": "not_modeled",
        "register_and_type_verification": "not_performed",
        "entry_reachability": "not_analyzed",
        "runtime_execution": "not_observed",
    }


class FlowParser:
    """One instance per APK, with budgets shared across ordinary DEX members."""

    def __init__(self, settings):
        self.attempted = self.retained = self.blocks = self.edges = 0
        self.settings = settings

    def __call__(self, raw, settings):
        methods, issues = [], []
        limited = False

        def consume(caller, code_offset, start, units, tries, registers):
            nonlocal limited
            if self.attempted >= settings.max_cfg_methods:
                limited = True
                return
            self.attempted += 1
            try:
                if units > settings.max_cfg_code_units:
                    raise InvalidFlow("cfg_method_code_limit")
                flow = build_method(
                    raw,
                    caller,
                    code_offset,
                    start,
                    units,
                    tries,
                    registers,
                    settings.max_cfg_blocks - self.blocks,
                    settings.max_cfg_edges - self.edges,
                )
                if (
                    self.blocks + len(flow["blocks"]) > settings.max_cfg_blocks
                    or self.edges + len(flow["edges"]) > settings.max_cfg_edges
                ):
                    raise InvalidFlow("cfg_output_budget")
            except InvalidFlow as exc:
                if str(exc) in {"cfg_method_code_limit", "cfg_output_budget"}:
                    limited = True
                if len(issues) < 100:
                    issues.append({"method_index": caller["method_index"], "code": str(exc)})
                else:
                    limited = True
                return
            methods.append(flow)
            self.retained += 1
            self.blocks += len(flow["blocks"])
            self.edges += len(flow["edges"])

        parsed = parse_calls(
            raw, settings, include_all_invokes=True, collect_calls=False, body_consumer=consume
        )
        partial = (
            limited
            or bool(issues)
            or parsed["coverage"] != "call_sites_decoded"
            or any(method["try_region_count"] for method in methods)
        )
        return {
            "sha256": parsed["sha256"],
            "version": parsed["version"],
            "counts": parsed["counts"],
            "coverage": "partial" if partial else "normal_targets_checked",
            "decoder": parsed["instruction_analysis"],
            "normal_flow": {
                "methods": methods,
                "issues": issues,
                "output_limited": limited,
                "block_scope": "this_method_in_this_dex_member_only",
                "exception_flow": "not_modeled",
                "runtime_execution": "not_observed",
            },
        }
