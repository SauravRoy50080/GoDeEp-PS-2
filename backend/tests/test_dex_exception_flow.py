"""Original bounded DEX fixtures test exception metadata and conservative graphs."""

import hashlib
import io
import random
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture, uleb

from godeep.analysis.static.calls import parse_calls
from godeep.analysis.static.control_flow import FlowParser
from godeep.core.config import Settings
from godeep.workers.runner import run_once


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and bool(byte & 64))
        result.append(byte if done else byte | 128)
        if done:
            return bytes(result)


def handler(typed=((0, 4),), catch_all=None):
    size = -len(typed) if catch_all is not None else len(typed)
    result = sleb(size) + b"".join(bytes(uleb(t)) + bytes(uleb(a)) for t, a in typed)
    return result + (bytes(uleb(catch_all)) if catch_all is not None else b"")


def fixture(words=(0x71, 0, 0, 0x0E, 0x0D, 0x0E), *, regions=None, handlers=None, padding=b"\0\0"):
    raw, code = code_fixture(struct.pack("<" + "H" * len(words), *words))
    raw = bytearray(raw)
    end = code + 16 + len(words) * 2
    regions = [(0, 3, 1)] if regions is None else regions
    handlers = bytes(uleb(1)) + handler() if handlers is None else handlers
    table = padding if len(words) % 2 and regions else b""
    table += b"".join(struct.pack("<IHH", *row) for row in regions)
    table += handlers if regions else b""
    raw[end:end] = table
    struct.pack_into("<H", raw, code + 6, len(regions))
    class_data = struct.unpack_from("<I", raw, 192 + 24)[0]
    struct.pack_into("<I", raw, 192 + 24, class_data + len(table))
    struct.pack_into("<I", raw, 32, len(raw))
    struct.pack_into("<I", raw, 104, len(raw) - 224)
    return bytes(raw), code, end


def parsed(raw=None, **config):
    settings = Settings(_env_file=None, **config)
    return FlowParser(settings, exception_aware=True)(raw or fixture()[0], settings)


def graph(raw=None, **config):
    result = parsed(raw, **config)
    assert result["exception_flow"]["methods"], result
    return result["exception_flow"]["methods"][0]


def issue(raw, expected, **config):
    result = parsed(raw, **config)
    assert not result["exception_flow"]["methods"]
    assert expected in {entry["code"] for entry in result["exception_flow"]["issues"]}
    assert result["coverage"] == "partial"
    return result


def test_typed_catch_offsets_boundaries_blocks_and_conservative_edges():
    raw, code, table_offset = fixture()
    result = parsed(raw)
    flow = graph(raw)
    assert result["coverage"] == "normal_and_exception_targets_checked"
    assert [block["start_code_unit"] for block in flow["blocks"]] == [0, 3, 4]
    table = flow["exception_tables"]
    assert table["regions"][0]["byte_offset"] == table_offset
    assert table["handlers"][0]["byte_offset"] == table_offset + 8 + 1
    edge = next(edge for edge in flow["edges"] if edge["kind"] == "exception_possible")
    assert edge["source"] == "block:0" and edge["target"] == "block:4"
    assert edge["type_descriptor"] == "Landroid/os/Debug;"  # Shape, not Throwable hierarchy.
    assert edge["byte_offset"] == code + 16
    assert edge["protected_end_code_unit_exclusive"] == 3
    assert edge["handler_entry_byte_offset"] == table_offset + 10
    assert edge["dispatch"] == "exception_type_matching_not_resolved"


@pytest.mark.parametrize("typed,catch_all", [((), 4), (((0, 4),), 5), (((0, 4), (1, 5)), None)])
def test_catch_all_and_typed_order(typed, catch_all):
    flow = graph(fixture(handlers=b"\x01" + handler(typed, catch_all))[0])
    catches = flow["exception_tables"]["handlers"][0]["catches"]
    assert [entry["order"] for entry in catches] == list(range(len(catches)))
    assert [entry["target_code_unit"] for entry in catches] == [a for _, a in typed] + (
        [catch_all] if catch_all is not None else []
    )
    assert len([edge for edge in flow["edges"] if edge["kind"] == "exception_possible"]) == len(
        catches
    )


def test_odd_padding_and_nonthrowing_protected_blocks_are_explicit_overapproximation():
    words = (0, 0x0E, 0x0D, 0x0E, 0x0E)
    raw, _, end = fixture(words, regions=[(0, 1, 1)], handlers=b"\x01" + handler((), 2))
    flow = graph(raw)
    assert flow["exception_tables"]["regions"][0]["byte_offset"] == end + 2
    assert any(
        edge["source"] == "block:0" and edge["kind"] == "exception_possible"
        for edge in flow["edges"]
    )
    raw, _, _ = fixture(
        words, regions=[(0, 1, 1)], handlers=b"\x01" + handler((), 2), padding=b"\x01\0"
    )
    issue(raw, "exception_padding_invalid")


def test_shared_handler_separate_regions_and_unreferenced_handler_records():
    first, second = handler((), 4), handler((), 5)
    raw, _, _ = fixture(regions=[(0, 3, 1), (3, 1, 1)], handlers=b"\x02" + first + second)
    flow = graph(raw)
    assert [entry["referenced"] for entry in flow["exception_tables"]["handlers"]] == [True, False]
    assert {
        edge["try_region_id"] for edge in flow["edges"] if edge["kind"] == "exception_possible"
    } == {"try:0", "try:1"}
    assert all(
        edge["target"] == "block:4"
        for edge in flow["edges"]
        if edge["kind"] == "exception_possible"
    )


@pytest.mark.parametrize(
    "regions,expected",
    [
        ([(0, 0, 1)], "exception_try_range_invalid"),
        ([(0, 7, 1)], "exception_try_range_invalid"),
        ([(3, 1, 1), (0, 3, 1)], "exception_try_range_invalid"),
        ([(0, 3, 1), (2, 2, 1)], "exception_try_range_invalid"),
        ([(1, 2, 1)], "exception_try_boundary_invalid"),
        ([(0, 2, 1)], "exception_try_boundary_invalid"),
        ([(0, 3, 0)], "exception_handler_offset_invalid"),
        ([(0, 3, 2)], "exception_handler_offset_invalid"),
    ],
)
def test_invalid_try_ranges_and_handler_references(regions, expected):
    issue(fixture(regions=regions)[0], expected)


@pytest.mark.parametrize(
    "encoded,expected",
    [
        (b"\xff\xff\xff\xff\x10", "exception_leb_invalid"),
        (b"\x01\x80\x80\x80\x80\x80\0", "exception_leb_invalid"),
        (b"\x01\xff\xff\xff\xff\x0f", "exception_leb_invalid"),
        (b"\x01" + handler(((4, 4),)), "exception_catch_type_invalid"),
        (b"\x01" + handler(((2, 4),)), "exception_catch_type_invalid"),
        (b"\x01" + handler(((0, 4), (0, 5))), "exception_catch_type_invalid"),
        (b"\x01" + handler(((0, 1),)), "exception_handler_target_invalid"),
        (b"\x01" + handler((), 6), "exception_handler_target_invalid"),
    ],
)
def test_invalid_lebs_types_and_handler_targets(encoded, expected):
    issue(fixture(handlers=encoded)[0], expected)


def test_payload_ranges_and_targets_rejected_without_publishing_partial_graphs():
    # goto +4 skips a two-unit instruction gap? Use goto +10 over a packed payload.
    words = (0x0E, 0x0E, 0x100, 1, 0, 0, 0, 0, 0x0D, 0x0E)
    raw, _, _ = fixture(words, regions=[(0, 9, 1)], handlers=b"\x01" + handler((), 8))
    issue(raw, "exception_try_contains_payload")
    raw, _, _ = fixture(words, regions=[(0, 1, 1)], handlers=b"\x01" + handler((), 2))
    issue(raw, "exception_handler_target_invalid")


@pytest.mark.parametrize(
    "config,regions,encoded,expected",
    [
        (
            {"max_exception_tries": 1},
            [(0, 3, 1), (3, 1, 1)],
            b"\x01" + handler(),
            "exception_try_limit",
        ),
        (
            {"max_exception_handlers": 1},
            [(0, 3, 1)],
            b"\x02" + handler() + handler(),
            "exception_handler_limit",
        ),
        (
            {"max_exception_catches": 1},
            [(0, 3, 1)],
            b"\x01" + handler(((0, 4), (1, 5))),
            "exception_catch_limit",
        ),
        (
            {"max_exception_table_bytes": 16},
            [(0, 3, 1), (3, 1, 1)],
            b"\x01" + handler(),
            "exception_table_byte_limit",
        ),
        ({"max_cfg_edges": 1}, [(0, 3, 1)], b"\x01" + handler(), "cfg_output_budget"),
        ({"max_cfg_blocks": 1}, [(0, 3, 1)], b"\x01" + handler(), "cfg_output_budget"),
    ],
)
def test_budgets_fail_without_method_fragments(config, regions, encoded, expected):
    output = issue(fixture(regions=regions, handlers=encoded)[0], expected, **config)
    assert output["exception_flow"]["output_limited"]


def test_data_section_bounds_and_no_try_fast_path_preserve_normal_decoder():
    raw, _, end = fixture()
    truncated = bytearray(raw)
    struct.pack_into("<I", truncated, 104, end + 9 - 224)
    # Keep class data in data section for the decoder, instead truncate physical handler tail
    # via the bounded table byte cap; separate direct reader checks exercise data bounds.
    from godeep.analysis.static.exceptions import InvalidException, read_tables

    with pytest.raises(InvalidException, match="exception_table_bounds"):
        read_tables(
            bytes(truncated),
            end - 12,
            6,
            1,
            ["Lx;"],
            try_budget=10,
            handler_budget=10,
            catch_budget=10,
            byte_budget=100,
        )
    raw = fixture(regions=[])[0]
    settings = Settings(_env_file=None)
    assert parse_calls(raw, settings) == parse_calls(raw, settings, type_consumer=None)
    old = FlowParser(settings)(raw, settings)["normal_flow"]["methods"][0]
    new = graph(raw)
    assert old["blocks"] == new["blocks"] and old["edges"] == new["edges"]
    assert not new["exception_tables"]["regions"]


def test_apk_wide_retained_metadata_budgets_across_members():
    settings = Settings(_env_file=None, max_exception_tries=1)
    parser = FlowParser(settings, exception_aware=True)
    assert parser(fixture()[0], settings)["exception_flow"]["methods"]
    result = parser(fixture()[0], settings)
    assert not result["exception_flow"]["methods"]
    assert parser.tries == 1 and parser.retained == 1
    assert result["exception_flow"]["output_limited"]


def test_extreme_signed_count_is_bounded_before_iteration():
    raw = fixture(handlers=b"\x01" + sleb(-2147483648))[0]
    issue(raw, "exception_catch_limit")


def test_seeded_malformed_table_variants_do_not_crash_or_publish_invalid_edges():
    rng = random.Random(5702)
    for _ in range(200):
        table = rng.randbytes(rng.randrange(1, 40))
        result = parsed(fixture(handlers=table)[0])
        for method in result["exception_flow"]["methods"]:
            ids = {block["id"] for block in method["blocks"]}
            assert all(edge["source"] in ids and edge["target"] in ids for edge in method["edges"])


def test_worker_catalog_multidex_config_snapshot_reports_and_html(intake):
    client, app, _ = intake
    app.state.settings.max_exception_tries = 1
    case = client.post("/api/v1/cases", json={"name": "Exception flow"}).json()["id"]
    apk = io.BytesIO()
    with ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", fixture()[0])
        archive.writestr("classes2.dex", fixture()[0])
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=apk.getvalue(),
        headers={"X-Filename": "exceptions.apk", "Content-Type": "application/octet-stream"},
    ).json()
    catalog = client.get("/api/v1/analyzers").json()
    assert (
        next(item for item in catalog if item["name"] == "dex_exception_flow")["apk_execution"]
        is False
    )
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample["id"], "adapter": "dex_exception_flow"},
    )
    assert job.status_code == 202, job.text
    assert job.json()["config"]["max_exception_tries"] == 1
    app.state.settings.max_exception_tries = 5  # The queued config remains authoritative.
    assert run_once(app.state.sessions, app.state.settings)
    result = client.get(f"/api/v1/cases/{case}/analyses/{job.json()['id']}/result")
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["adapter_version"] == "1.0.0"
    assert data["exception_flow_summary"]["retained_try_regions"] == 1
    assert data["exception_flow_summary"]["attempted_methods"] == 2
    assert data["input_sha256"] == hashlib.sha256(apk.getvalue()).hexdigest()
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}/reports"
    report = client.post(prefix, json={"job_ids": [job.json()["id"]]})
    assert report.status_code == 201, report.text
    uri = prefix + f"/{report.json()['id']}"
    saved = client.get(uri + "/download").json()
    assert saved["analyses"][0]["data"] == data
    assert "exception_possible" in client.get(uri + "/export/html").text
    other = client.post("/api/v1/cases", json={"name": "other"}).json()["id"]
    assert client.get(uri.replace(case, other) + "/download").status_code == 404
