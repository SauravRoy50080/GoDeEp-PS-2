"""Bounded DEX exception tables; syntactic metadata, never exception feasibility."""

import re
import struct


class InvalidException(ValueError):
    pass


def read_tables(
    raw, start, units, tries, types, *, try_budget, handler_budget, catch_budget, byte_budget
):
    if not tries:
        return {
            "regions": [],
            "handlers": [],
            "typed_catch_count": 0,
            "table_bytes": 0,
            "table_start_byte": None,
        }
    if tries > try_budget:
        raise InvalidException("exception_try_limit")
    data_size, data_start = struct.unpack_from("<II", raw, 104)
    origin = start + units * 2
    end = min(len(raw), data_start + data_size, origin + byte_budget)

    def check(pos, size):
        if pos < data_start or size < 0 or pos + size > end:
            if pos + size > origin + byte_budget:
                raise InvalidException("exception_table_byte_limit")
            raise InvalidException("exception_table_bounds")

    pos = origin
    if units % 2:
        check(pos, 2)
        if raw[pos : pos + 2] != b"\0\0":
            raise InvalidException("exception_padding_invalid")
        pos += 2
    check(pos, tries * 8)
    regions, previous_end = [], 0
    for index in range(tries):
        offset = pos + index * 8
        first, count, handler_offset = struct.unpack_from("<IHH", raw, offset)
        if not count or first < previous_end or first + count > units:
            raise InvalidException("exception_try_range_invalid")
        previous_end = first + count
        regions.append(
            {
                "id": f"try:{index}",
                "byte_offset": offset,
                "start_code_unit": first,
                "end_code_unit_exclusive": first + count,
                "handler_offset": handler_offset,
            }
        )
    pos += tries * 8
    handler_start = pos

    def leb(signed=False):
        nonlocal pos
        value = 0
        for shift in range(0, 35, 7):
            check(pos, 1)
            byte = raw[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                if signed and byte & 64:
                    value -= 1 << (shift + 7)
                low, high = (-2147483648, 2147483647) if signed else (0, 4294967295)
                if not low <= value <= high:
                    raise InvalidException("exception_leb_invalid")
                return value
        raise InvalidException("exception_leb_invalid")

    handler_count = leb()
    if handler_count > handler_budget:
        raise InvalidException("exception_handler_limit")
    handlers, typed_total = [], 0
    by_offset = {}
    for _ in range(handler_count):
        offset = pos - handler_start
        handler = {
            "id": f"handler:{offset}",
            "handler_offset": offset,
            "byte_offset": pos,
            "catches": [],
        }
        size = leb(signed=True)
        typed_total += abs(size)
        if typed_total > catch_budget:
            raise InvalidException("exception_catch_limit")
        seen = set()
        for catch_index in range(abs(size)):
            pair_offset = pos
            type_index, target = leb(), leb()
            if type_index >= len(types) or type_index in seen:
                raise InvalidException("exception_catch_type_invalid")
            descriptor = types[type_index]
            if re.fullmatch(r"L[^.;\[\x00-\x20]+;", descriptor) is None:
                raise InvalidException("exception_catch_type_invalid")
            seen.add(type_index)
            handler["catches"].append(
                {
                    "order": catch_index,
                    "kind": "typed",
                    "type_index": type_index,
                    "type_descriptor": descriptor,
                    "target_code_unit": target,
                    "byte_offset": pair_offset,
                }
            )
        if size <= 0:
            pair_offset = pos
            handler["catches"].append(
                {
                    "order": abs(size),
                    "kind": "catch_all",
                    "type_index": None,
                    "type_descriptor": None,
                    "target_code_unit": leb(),
                    "byte_offset": pair_offset,
                }
            )
        by_offset[offset] = handler
        handlers.append(handler)
    referenced = set()
    for region in regions:
        handler = by_offset.get(region["handler_offset"])
        if handler is None:
            raise InvalidException("exception_handler_offset_invalid")
        region["handler_id"] = handler["id"]
        referenced.add(handler["id"])
    for handler in handlers:
        handler["referenced"] = handler["id"] in referenced
    return {
        "regions": regions,
        "handlers": handlers,
        "typed_catch_count": typed_total,
        "table_bytes": pos - origin,
        "table_start_byte": origin,
    }


def boundaries(table, instructions, units):
    """Reject operand/payload targets and intervals spanning undecoded data gaps."""
    leaders = set()
    ends = {instruction["end"] for instruction in instructions.values()}
    # Prefix sums allow many regions without repeatedly walking the entire stream.
    positions = sorted(instructions)
    covered_units = [0] * (units + 1)
    for pos in positions:
        covered_units[pos + 1] = instructions[pos]["end"] - pos
    for pos in range(units):
        covered_units[pos + 1] += covered_units[pos]
    for region in table["regions"]:
        first, end = region["start_code_unit"], region["end_code_unit_exclusive"]
        if first not in instructions or end not in ends:
            raise InvalidException("exception_try_boundary_invalid")
        # Sum instruction widths in [first,end); an operand/payload gap cannot pass.
        width = covered_units[end] - covered_units[first]
        if width != end - first:
            raise InvalidException("exception_try_contains_payload")
        leaders.add(first)
        if end in instructions:
            leaders.add(end)
    for handler in table["handlers"]:
        for catch in handler["catches"]:
            target = catch["target_code_unit"]
            if target not in instructions:
                raise InvalidException("exception_handler_target_invalid")
            leaders.add(target)
    return leaders
