"""Bounded class-data/code-item traversal and linear instruction call evidence."""

import struct
from importlib.metadata import version

from androguard.core.dex import DALVIK_OPCODES_FORMAT

from godeep.analysis.static.dex import RULES, parse_dex


class InvalidCode(Exception):
    pass


def parse_calls(raw, settings):
    result = parse_dex(raw, settings, include_tables=True)
    strings, types, methods = result.pop("_tables")
    calls, issues = [], []
    stats = {
        "encoded_methods": 0,
        "encoded_fields": 0,
        "bodies_decoded": 0,
        "instructions": 0,
        "code_units": 0,
        "matched_calls": 0,
    }
    limited = False

    def issue(code, method=None):
        nonlocal limited
        if len(issues) < 100:
            issues.append({"code": code, "method_index": method})
        else:
            limited = True

    def check(offset, size):
        if offset < 0 or size < 0 or offset + size > len(raw):
            raise InvalidCode("dex_code_bounds_invalid")

    def u32(offset):
        check(offset, 4)
        return struct.unpack_from("<I", raw, offset)[0]

    data_size, data_start = u32(104), u32(108)

    def data_check(offset, size):
        check(offset, size)
        if offset < data_start or offset + size > data_start + data_size:
            raise InvalidCode("dex_data_bounds_invalid")

    def uleb(pos):
        value = 0
        for shift in range(0, 35, 7):
            data_check(pos, 1)
            byte = raw[pos]
            pos += 1
            if shift == 28 and byte > 15:
                raise InvalidCode("dex_uleb_invalid")
            value |= (byte & 127) << shift
            if not byte & 128:
                return value, pos
        raise InvalidCode("dex_uleb_invalid")

    def identity(index):
        if index >= len(methods):
            raise InvalidCode("dex_method_index_invalid")
        cls, proto, name = methods[index]
        proto_offset = u32(76) + 12 * proto
        shorty, return_type, parameters = (u32(proto_offset + k) for k in (0, 4, 8))
        if shorty >= len(strings) or return_type >= len(types):
            raise InvalidCode("dex_proto_invalid")
        arguments = []
        if parameters:
            if parameters % 4:
                raise InvalidCode("dex_proto_invalid")
            data_check(parameters, 4)
            count = u32(parameters)
            if count > settings.max_dex_identifiers:
                raise InvalidCode("dex_proto_limit")
            data_check(parameters + 4, count * 2)
            for i in range(count):
                type_id = struct.unpack_from("<H", raw, parameters + 4 + i * 2)[0]
                if type_id >= len(types):
                    raise InvalidCode("dex_proto_invalid")
                arguments.append(types[type_id])
        return {
            "method_index": index,
            "class_descriptor": types[cls],
            "method_name": strings[name],
            "descriptor": "(" + "".join(arguments) + ")" + types[return_type],
        }

    def decode(method, code_offset, flags):
        nonlocal limited
        if code_offset % 4 or flags & (0x100 | 0x400):
            raise InvalidCode("dex_code_header_invalid")
        data_check(code_offset, 16)
        registers, ins, outs, tries, debug, units = struct.unpack_from("<4H2I", raw, code_offset)
        if units == 0 or ins > registers:
            raise InvalidCode("dex_code_header_invalid")
        start, length = code_offset + 16, units * 2
        data_check(start, length)
        if stats["code_units"] + units > settings.max_dex_code_units:
            raise InvalidCode("dex_code_limit")
        stats["code_units"] += units
        caller = identity(method)
        pending = []
        pos = 0
        while pos < length:
            opcode = raw[start + pos]
            word = struct.unpack_from("<H", raw, start + pos)[0]
            if opcode == 0 and word:
                if pos % 4:
                    raise InvalidCode("dex_payload_alignment_invalid")
                remaining = length - pos
                if word in (0x100, 0x200):
                    if remaining < (8 if word == 0x100 else 4):
                        raise InvalidCode("dex_payload_invalid")
                    count = struct.unpack_from("<H", raw, start + pos + 2)[0]
                    width = (8 + count * 4) if word == 0x100 else (4 + count * 8)
                elif word == 0x300:
                    if remaining < 8:
                        raise InvalidCode("dex_payload_invalid")
                    element, count = struct.unpack_from("<HI", raw, start + pos + 2)
                    if element not in (1, 2, 4, 8):
                        raise InvalidCode("dex_payload_invalid")
                    width = 8 + ((element * count + 1) // 2) * 2
                else:
                    raise InvalidCode("dex_payload_invalid")
            else:
                entry = DALVIK_OPCODES_FORMAT.get(opcode)
                if entry is None or entry[1][0] == "unused":
                    raise InvalidCode("dex_opcode_unsupported")
                width = entry[0].length
            if width <= 0 or pos + width > length:
                raise InvalidCode("dex_instruction_truncated")
            stats["instructions"] += 1
            if opcode in (0xFA, 0xFB, 0xFC, 0xFD):
                issue("dex_indirect_invoke_unresolved", method)
            if opcode in (*range(0x6E, 0x73), *range(0x74, 0x79)):
                target = struct.unpack_from("<H", raw, start + pos + 2)[0]
                if target >= len(methods):
                    raise InvalidCode("dex_method_index_invalid")
                if opcode <= 0x72:
                    count = word >> 12
                    if count > 5:
                        raise InvalidCode("dex_invoke_registers_invalid")
                    last = struct.unpack_from("<H", raw, start + pos + 4)[0]
                    operands = [(last >> (4 * i)) & 15 for i in range(4)] + [(word >> 8) & 15]
                    if any(reg >= registers for reg in operands[:count]):
                        raise InvalidCode("dex_invoke_registers_invalid")
                else:
                    count = word >> 8
                    first = struct.unpack_from("<H", raw, start + pos + 4)[0]
                    if count and first + count > registers:
                        raise InvalidCode("dex_invoke_registers_invalid")
                if count > outs:
                    raise InvalidCode("dex_invoke_outs_invalid")
                cls, _, name = methods[target]
                category = RULES.get((types[cls], strings[name]))
                if category:
                    stats["matched_calls"] += 1
                    if len(calls) + len(pending) < settings.max_dex_findings:
                        pending.append(
                            {
                                "caller": caller,
                                "target": identity(target),
                                "opcode": DALVIK_OPCODES_FORMAT[opcode][1][0],
                                "instruction_offset_bytes": pos,
                                "instruction_offset_code_units": pos // 2,
                                "byte_offset": start + pos,
                                "code_item_offset": code_offset,
                                "rule_id": "DEX." + category.upper(),
                                "evidence_state": "decoded_invoke_instruction",
                                "requires_review": True,
                            }
                        )
                    else:
                        limited = True
            pos += width
        # Publish only after the entire instruction stream decodes successfully.
        calls.extend(pending)
        stats["bodies_decoded"] += 1

    try:
        check(data_start, data_size)
        if data_start < 112:
            raise InvalidCode("dex_data_bounds_invalid")
        classes, offset = u32(96), u32(100)
        if classes > settings.max_dex_identifiers:
            raise InvalidCode("dex_class_limit")
        if classes and (offset < 112 or offset % 4):
            raise InvalidCode("dex_class_bounds_invalid")
        check(offset, classes * 32)
        seen = set()
        for i in range(classes):
            base = offset + i * 32
            class_id, class_data = u32(base), u32(base + 24)
            if class_id >= len(types):
                raise InvalidCode("dex_class_index_invalid")
            if not class_data:
                continue
            counts, pos = [], class_data
            for _ in range(4):
                value, pos = uleb(pos)
                counts.append(value)
            if sum(counts) > settings.max_dex_encoded_methods:
                raise InvalidCode("dex_encoded_member_limit")
            for count in counts[:2]:
                index = 0
                for n in range(count):
                    diff, pos = uleb(pos)
                    flags, pos = uleb(pos)
                    stats["encoded_fields"] += 1
                    if stats["encoded_fields"] > settings.max_dex_encoded_methods:
                        raise InvalidCode("dex_encoded_member_limit")
                    index += diff
                    if index >= u32(80) or (n and diff == 0):
                        raise InvalidCode("dex_field_index_invalid")
            for count in counts[2:]:
                index = 0
                for n in range(count):
                    diff, pos = uleb(pos)
                    flags, pos = uleb(pos)
                    code, pos = uleb(pos)
                    index += diff
                    stats["encoded_methods"] += 1
                    if stats["encoded_methods"] > settings.max_dex_encoded_methods:
                        raise InvalidCode("dex_encoded_member_limit")
                    if index >= len(methods) or (n and diff == 0) or index in seen:
                        raise InvalidCode("dex_method_index_invalid")
                    seen.add(index)
                    if methods[index][0] != class_id:
                        raise InvalidCode("dex_method_owner_invalid")
                    if code:
                        try:
                            decode(index, code, flags)
                        except InvalidCode as exc:
                            issue(str(exc), index)
                    elif not flags & (0x100 | 0x400):
                        issue("dex_concrete_method_without_code", index)
    except InvalidCode as exc:
        issue(str(exc))
    result["call_sites"] = calls
    result["instruction_analysis"] = {
        "tool_versions": {"androguard": version("androguard")},
        "coverage": "partial"
        if issues or limited
        else "linear_sweep_decoded"
        if stats["bodies_decoded"]
        else "no_method_bodies",
        "issues": issues,
        "output_limited": limited,
        "counts": stats,
        "reachability": "not_analyzed",
        "runtime_execution": "not_observed",
        "exception_handlers_and_control_flow": "not_validated",
    }
    result["coverage"] = (
        "call_sites_decoded"
        if (
            result["coverage"] == "identifier_tables_parsed"
            and not issues
            and not limited
            and stats["bodies_decoded"] > 0
        )
        else "partial"
    )
    return result
