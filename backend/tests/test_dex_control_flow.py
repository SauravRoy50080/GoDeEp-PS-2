"""Normal-flow target validation with bounded original DEX fixtures."""

import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture

from godeep.analysis.static.calls import parse_calls
from godeep.analysis.static.control_flow import FlowParser
from godeep.core.config import Settings
from godeep.workers.runner import run_once


def parsed(words, **config):
    raw, offset = code_fixture(struct.pack("<" + "H" * len(words), *words))
    settings = Settings(_env_file=None, **config)
    return FlowParser(settings)(raw, settings), offset


def method(words):
    return parsed(words)[0]["normal_flow"]["methods"][0]


def test_default_decoder_unchanged_and_linear_block_offsets():
    raw, start = code_fixture()
    settings = Settings(_env_file=None)
    assert parse_calls(raw, settings) == parse_calls(
        raw, settings, collect_calls=True, body_consumer=None
    )
    output = FlowParser(settings)(raw, settings)
    graph = output["normal_flow"]["methods"][0]
    assert output["coverage"] == "normal_targets_checked"
    assert len(graph["blocks"]) == 1 and graph["edges"] == []
    assert graph["blocks"][0]["byte_offset"] == start + 16
    assert graph["blocks"][0]["end_code_unit_exclusive"] == 4
    assert graph["entry_reachability"] == "not_analyzed"


@pytest.mark.parametrize("op", range(0x32, 0x3E))
def test_conditional_branch_has_taken_and_fallthrough_edges(op):
    graph = method([op, 3, 0x0E, 0x0E])
    assert [block["start_code_unit"] for block in graph["blocks"]] == [0, 2, 3]
    assert [(edge["target"], edge["kind"]) for edge in graph["edges"]] == [
        ("block:3", "branch_taken"),
        ("block:2", "fallthrough"),
    ]


@pytest.mark.parametrize(
    "words", [[0x0228, 0x0E, 0x0E], [0x29, 3, 0x0E, 0x0E], [0x2A, 4, 0, 0x0E, 0x0E]]
)
def test_goto_widths_preserve_disconnected_blocks(words):
    graph = method(words)
    assert graph["edges"][0]["kind"] == "goto"
    assert len(graph["blocks"]) == 3


def test_backward_loop_and_legal_goto32_self_loop():
    graph = method([0, 0xFF28])
    assert graph["edges"][0]["source"] == graph["edges"][0]["target"] == "block:0"
    graph = method([0x2A, 0, 0])
    assert graph["edges"][0]["source"] == graph["edges"][0]["target"]


def switch(op, keys=(7, 8), targets=(3, 3)):
    # switch at unit 0, return at unit 3, aligned payload at unit 4.
    if op == 0x2B:
        payload = struct.pack("<HHi", 0x100, len(keys), keys[0])
    else:
        payload = struct.pack("<HH", 0x200, len(keys)) + struct.pack("<" + "i" * len(keys), *keys)
    payload += struct.pack("<" + "i" * len(targets), *targets)
    return [op, 4, 0, 0x0E] + list(struct.unpack("<" + "H" * (len(payload) // 2), payload))


@pytest.mark.parametrize("op", [0x2B, 0x2C])
def test_switch_payload_cases_are_relative_to_opcode_not_table(op):
    graph = method(switch(op))
    assert graph["payload_count"] == 1
    assert len(graph["blocks"]) == 2
    assert [edge.get("case_value") for edge in graph["edges"]] == [7, 8, None]
    assert all(edge["target"] == "block:3" for edge in graph["edges"])
    assert graph["blocks"][-1]["end_code_unit_exclusive"] == 4


def test_fill_array_data_reference_is_not_branch_edge():
    graph = method([0x26, 4, 0, 0x0E, 0x300, 1, 1, 0, 0x71])
    assert graph["payload_count"] == 1 and graph["edges"] == []
    assert graph["blocks"][0]["instruction_count"] == 2


@pytest.mark.parametrize(
    "words",
    [
        [0x28],
        [0x29, 0],
        [0x38, 0, 0x0E],  # forbidden zero deltas
        [0x28 | (1 << 8), 0x29, 1, 0x0E],  # branch into operand
        [0x0228],  # outside method
        [0],  # falls beyond method
        [0x138, 2, 0x0E],  # invalid tested register
        [0x2B, 3, 0, 0x0E],  # switch points at instruction, not payload
        switch(0x2B, targets=(4, 3)),  # case into payload
        switch(0x2C, keys=(8, 7)),  # unsorted keys
        switch(0x2C, keys=(7, 7)),  # duplicate keys
        [0x26, 4, 0, 0x0E, 0x100, 0, 0, 0],  # wrong array payload kind
    ],
)
def test_invalid_targets_publish_no_method_graph(words):
    output, _ = parsed(words)
    assert output["coverage"] == "partial"
    assert output["normal_flow"]["methods"] == []
    assert output["normal_flow"]["issues"]


def test_linear_decode_failure_never_reaches_flow_builder():
    output, _ = parsed([0x71])
    assert output["normal_flow"]["methods"] == []
    assert output["decoder"]["issues"]


def test_try_regions_remain_partial_without_exception_claims():
    raw, offset = code_fixture(b"\x0e\0")
    raw = bytearray(raw)
    struct.pack_into("<H", raw, offset + 6, 1)
    settings = Settings(_env_file=None)
    output = FlowParser(settings)(bytes(raw), settings)
    assert output["coverage"] == "partial"
    graph = output["normal_flow"]["methods"][0]
    assert graph["try_region_count"] == 1 and graph["exception_flow"] == "not_modeled"


def test_per_method_and_global_budgets_do_not_publish_half_graphs():
    output, _ = parsed([0x38, 3, 0x0E, 0x0E], max_cfg_blocks=1)
    assert output["normal_flow"]["methods"] == []
    assert output["normal_flow"]["output_limited"]
    output, _ = parsed([0x38, 3, 0x0E, 0x0E], max_cfg_edges=1)
    assert output["normal_flow"]["methods"] == []
    output, _ = parsed([0, 0x0E], max_cfg_code_units=1)
    assert output["normal_flow"]["output_limited"]
    settings = Settings(_env_file=None, max_cfg_methods=1)
    parser = FlowParser(settings)
    raw = code_fixture(b"\x0e\0")[0]
    assert parser(raw, settings)["normal_flow"]["methods"]
    second = parser(raw, settings)
    assert second["normal_flow"]["methods"] == []
    assert second["normal_flow"]["output_limited"]


def test_real_multidex_worker_configuration_report_and_case_scope(intake):
    client, app, _ = intake
    app.state.settings.max_cfg_methods = 1
    case = client.post("/api/v1/cases", json={"name": "Normal flow"}).json()["id"]
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        for name in ("classes.dex", "classes2.dex"):
            archive.writestr(name, code_fixture()[0])
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=buffer.getvalue(),
        headers={
            "X-Filename": "flow.apk",
            "Content-Type": "application/octet-stream",
        },
    ).json()
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={
            "sample_id": sample["id"],
            "adapter": "dex_control_flow",
        },
    )
    assert job.status_code == 202, job.text
    job = job.json()
    assert job["config"]["max_cfg_methods"] == 1
    assert run_once(app.state.sessions, app.state.settings)
    result = client.get(f"/api/v1/cases/{case}/analyses/{job['id']}/result")
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["coverage"] == "partial"
    assert data["normal_flow_summary"]["retained_methods"] == 1
    prefix = f"/api/v1/cases/{case}/samples/{sample['id']}/reports"
    report = client.post(prefix, json={"job_ids": [job["id"]]})
    assert report.status_code == 201, report.text
    artifact = client.get(prefix + f"/{report.json()['id']}/download").json()
    assert artifact["analyses"][0]["data"]["adapter"] == "dex_control_flow"
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404


def test_switch_expansion_is_bounded_before_retaining_case_edges():
    words = switch(0x2B, keys=tuple(range(100)), targets=(3,) * 100)
    output, _ = parsed(words, max_cfg_edges=10)
    assert output["normal_flow"]["methods"] == []
    assert output["normal_flow"]["output_limited"]
    assert output["normal_flow"]["issues"][0]["code"] == "cfg_output_budget"
