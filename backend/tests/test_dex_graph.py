"""All-invoke evidence graphs retain operands without reachability claims."""

import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_calls import code_fixture
from test_dex_static import dex_fixture

from godeep.analysis.static.calls import parse_calls
from godeep.analysis.static.graph import GraphParser
from godeep.core.config import Settings
from godeep.workers.runner import run_once


def parse(raw, **settings):
    options = Settings(_env_file=None, **settings)
    return GraphParser(options)(raw, options)


def test_sensitive_call_default_compatibility_and_graph_offsets():
    raw, offset = code_fixture()
    options = Settings(_env_file=None)
    assert parse_calls(raw, options) == parse_calls(raw, options, include_all_invokes=False)
    result = parse(raw)
    graph = result["invoke_graph"]
    assert result["coverage"] == "graph_edges_extracted"
    assert graph["retained_nodes"] == 2 and graph["retained_edges"] == 1
    edge = graph["edges"][0]
    assert edge["byte_offset"] == offset + 16
    assert edge["sensitive_rule_id"] == "DEX.DEBUGGER_CHECK"
    assert edge["caller"] == "method:1" and edge["target"] == "method:0"
    assert graph["runtime_execution"] == "not_observed" and graph["reachability"] == "not_analyzed"
    assert graph["target_resolution"] == "method_id_operand_only"


def test_non_sensitive_method_is_retained_without_synthetic_sensitive_rule():
    raw, _ = code_fixture()
    changed = raw.replace(b"isDebuggerConnected", b"isDebuggerConnectex")
    assert len(changed) == len(raw)
    assert parse_calls(changed, Settings(_env_file=None))["call_sites"] == []
    graph = parse(changed)["invoke_graph"]
    assert graph["retained_edges"] == 1
    assert graph["edges"][0]["sensitive_rule_id"] is None
    target = next(node for node in graph["nodes"] if node["id"] == "method:0")
    assert target["method"]["method_name"] == "isDebuggerConnectex"


def test_recursive_operand_shares_node_without_graph_traversal():
    raw, _ = code_fixture(b"\x71\0\x01\0\0\0\x0e\0")
    graph = parse(raw)["invoke_graph"]
    assert len(graph["nodes"]) == 1 and len(graph["edges"]) == 1
    assert set(graph["nodes"][0]["roles"]) == {"caller", "target_operand"}
    assert graph["edges"][0]["caller"] == graph["edges"][0]["target"]


@pytest.mark.parametrize("opcode", [0x71, 0x77])
def test_ordinary_and_range_opcodes_retained(opcode):
    raw, _ = code_fixture(bytes([opcode, 0, 0, 0, 0, 0, 14, 0]))
    assert parse(raw)["invoke_graph"]["edges"][0]["opcode"].startswith("invoke-static")


def test_duplicate_targets_keep_distinct_instruction_evidence():
    raw, _ = code_fixture(b"\x71\0\0\0\0\0" * 2 + b"\x0e\0")
    graph = parse(raw)["invoke_graph"]
    assert graph["retained_nodes"] == 2 and graph["retained_edges"] == 2
    assert len({edge["byte_offset"] for edge in graph["edges"]}) == 2


@pytest.mark.parametrize(
    "instructions", [b"\x71\0\0\0\0\0\x73\0", b"\x71\0\x63\0\0\0", b"\x71\0\0\0\0\0\x71\0"]
)
def test_malformed_method_discards_all_pending_graph_edges(instructions):
    raw, _ = code_fixture(instructions)
    result = parse(raw)
    assert result["coverage"] == "partial"
    assert result["invoke_graph"]["nodes"] == result["invoke_graph"]["edges"] == []


def test_payload_and_identifier_only_data_do_not_create_edges():
    payload = struct.pack("<HHii", 0x100, 1, 0x71, 0)
    raw, _ = code_fixture(b"\x0e\0\0\0" + payload)
    assert parse(raw)["invoke_graph"]["edges"] == []
    result = parse(dex_fixture())
    assert result["coverage"] == "partial" and result["invoke_graph"]["edges"] == []


def test_edge_budget_shared_across_members_and_node_budget_explicit():
    raw, _ = code_fixture()
    settings = Settings(_env_file=None, max_graph_edges=1)
    parser = GraphParser(settings)
    first, second = parser(raw, settings), parser(raw, settings)
    assert first["invoke_graph"]["retained_edges"] == 1
    assert second["invoke_graph"]["retained_edges"] == 0 and second["coverage"] == "partial"
    assert parser.edges == 1 and parser.nodes == 2
    limited = parse(raw, max_graph_nodes=1)
    assert limited["coverage"] == "partial" and limited["invoke_graph"]["node_output_limited"]
    assert not limited["invoke_graph"]["edges"]


def test_unreachable_linear_instruction_stays_unverified():
    raw, _ = code_fixture(b"\x0e\0\x71\0\0\0\0\0")
    graph = parse(raw)["invoke_graph"]
    assert graph["edges"][0]["instruction_offset_bytes"] == 2
    assert graph["reachability"] == "not_analyzed"


def test_multi_dex_worker_report_case_scope_and_total_budgets(intake):
    client, app, _ = intake
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", code_fixture()[0])
        archive.writestr("classes2.dex", code_fixture()[0])
    case = client.post("/api/v1/cases", json={"name": "Graph"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=buffer.getvalue(),
        headers={"Content-Type": "application/octet-stream", "X-Filename": "graph.apk"},
    ).json()
    app.state.settings.max_graph_edges = 1
    response = client.post(
        f"/api/v1/cases/{case}/analyses", json={"sample_id": sample["id"], "adapter": "dex_graph"}
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["config"]["max_graph_edges"] == 1
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["graph_summary"]["retained_edges"] == 1
    assert data["coverage"] == "partial" and len(data["dex_files"]) == 2
    assert data["dex_files"][0]["member"] == "classes.dex"
    assert data["dex_files"][0]["sha256"]
    report = client.post(
        f"/api/v1/cases/{case}/samples/{sample['id']}/reports", json={"job_ids": [job["id"]]}
    )
    assert report.status_code == 201, report.text
    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]
    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404


def test_graph_prototype_aggregation_is_bounded_without_changing_default_mode():
    raw, _ = code_fixture()
    data = bytearray(raw)
    data.extend(bytes(-len(data) % 4))
    parameters = len(data)
    data.extend(struct.pack("<I4H", 4, 0, 0, 0, 0))
    struct.pack_into("<I", data, 160, parameters)
    struct.pack_into("<I", data, 32, len(data))
    struct.pack_into("<I", data, 104, len(data) - 224)
    settings = Settings(_env_file=None, max_dex_string_bytes=64)
    assert parse_calls(bytes(data), settings)["call_sites"]
    graph = GraphParser(settings)(bytes(data), settings)
    assert graph["coverage"] == "partial" and not graph["invoke_graph"]["edges"]
    assert graph["instruction_analysis"]["issues"][0]["code"] == "dex_graph_prototype_limit"
