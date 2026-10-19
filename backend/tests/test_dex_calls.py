"""Original class-data/code-item fixtures exercise real opcode boundaries."""

import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from test_dex_static import dex_fixture

from godeep.analysis.static.calls import parse_calls
from godeep.core.config import Settings
from godeep.workers.runner import run_once


def uleb(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return out


def code_fixture(instructions=b"\x71\0\0\0\0\0\x0e\0", *, code_flags=9):
    strings = ["Landroid/os/Debug;", "Lfixture/Main;", "Z", "V", "isDebuggerConnected", "run"]
    so, to, po, mo, co = 112, 136, 152, 176, 192
    data_start = 224
    raw = bytearray(data_start)
    raw[:8] = b"dex\n035\0"
    struct.pack_into("<II", raw, 36, 112, 0x12345678)
    for header, count, offset in [(56, 6, so), (64, 4, to), (72, 2, po), (88, 2, mo), (96, 1, co)]:
        struct.pack_into("<II", raw, header, count, offset)
    for i, string in enumerate(strings):
        struct.pack_into("<I", raw, so + i * 4, len(raw))
        raw.extend(uleb(len(string)))
        raw.extend(string.encode() + b"\0")
    for i in range(4):
        struct.pack_into("<I", raw, to + i * 4, i)
    struct.pack_into("<III", raw, po, 2, 2, 0)
    struct.pack_into("<III", raw, po + 12, 3, 3, 0)
    struct.pack_into("<HHI", raw, mo, 0, 0, 4)
    struct.pack_into("<HHI", raw, mo + 8, 1, 1, 5)
    raw.extend(b"\0" * (-len(raw) % 4))
    code_offset = len(raw)
    raw.extend(struct.pack("<4H2I", 1, 0, 1, 0, 0, len(instructions) // 2))
    raw.extend(instructions)
    class_data = len(raw)
    raw.extend(b"\0\0\x01\0" + uleb(1) + uleb(code_flags) + uleb(code_offset))
    struct.pack_into("<8I", raw, co, 1, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, class_data, 0)
    struct.pack_into("<I", raw, 32, len(raw))
    struct.pack_into("<II", raw, 104, len(raw) - data_start, data_start)
    return bytes(raw), code_offset


@pytest.mark.parametrize("opcode", [0x71, 0x77])
def test_caller_target_and_instruction_evidence(opcode):
    raw, offset = code_fixture(bytes([opcode, 0, 0, 0, 0, 0, 14, 0]))
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["coverage"] == "call_sites_decoded"
    call = result["call_sites"][0]
    assert call["caller"]["class_descriptor"] == "Lfixture/Main;"
    assert call["caller"]["descriptor"] == "()V"
    assert call["target"]["method_name"] == "isDebuggerConnected"
    assert call["target"]["descriptor"] == "()Z"
    assert call["byte_offset"] == offset + 16
    assert call["instruction_offset_code_units"] == 0
    assert call["evidence_state"] == "decoded_invoke_instruction"
    assert result["instruction_analysis"]["runtime_execution"] == "not_observed"


def test_identifier_reference_without_call_does_not_create_call():
    raw, _ = code_fixture(b"\x0e\0")
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["api_references"] and result["call_sites"] == []
    assert result["instruction_analysis"]["counts"]["bodies_decoded"] == 1


def test_payload_data_is_not_interpreted_as_invokes():
    # A packed-switch payload contains bytes resembling invoke-static.
    payload = struct.pack("<HHii", 0x100, 1, 0x71, 0)
    raw, _ = code_fixture(b"\x0e\0\0\0" + payload)
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["call_sites"] == []
    assert result["coverage"] == "call_sites_decoded"


@pytest.mark.parametrize(
    "instructions",
    [
        b"\x71\0\0\0\0\0\x71\0",  # truncated later invoke discards earlier finding
        b"\x71\0\x63\0\0\0",  # invalid target index
        b"\x71\x60\0\0\0\0",  # invalid 35c count
        b"\x77\x02\0\0\0\0",  # invalid range registers
        b"\x73\0",  # reserved opcode
        b"\0\x03\0\0",  # truncated payload
    ],
)
def test_invalid_method_stream_has_no_call_findings(instructions):
    raw, _ = code_fixture(instructions)
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["call_sites"] == []
    assert result["coverage"] == "partial"
    assert result["instruction_analysis"]["issues"]


def test_code_limits_and_no_method_bodies_are_explicit():
    raw, _ = code_fixture()
    result = parse_calls(raw, Settings(_env_file=None, max_dex_code_units=1))
    assert result["instruction_analysis"]["issues"][0]["code"] == "dex_code_limit"
    assert result["call_sites"] == []
    result = parse_calls(dex_fixture(), Settings(_env_file=None))
    assert result["instruction_analysis"]["coverage"] == "no_method_bodies"
    assert result["coverage"] == "partial"


def test_native_flag_with_code_is_not_accepted():
    raw, _ = code_fixture(code_flags=0x109)
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["call_sites"] == []
    assert result["instruction_analysis"]["issues"][0]["code"] == "dex_code_header_invalid"


def test_unreachable_instruction_is_not_labelled_executed():
    raw, _ = code_fixture(b"\x0e\0\x71\0\0\0\0\0")
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["call_sites"][0]["instruction_offset_bytes"] == 2
    assert result["instruction_analysis"]["reachability"] == "not_analyzed"


def test_real_worker_produces_call_evidence(intake):
    client, app, _ = intake
    raw, _ = code_fixture()
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        archive.writestr("classes.dex", raw)
    case = client.post("/api/v1/cases", json={"name": "Call-site investigation"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "calls.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201
    queued = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "dex_calls"},
    )
    assert queued.status_code == 202, queued.text
    job = queued.json()
    assert job["config"]["max_dex_code_units"] == 1000000
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["adapter"] == "dex_calls" and data["coverage"] == "call_sites_decoded"
    assert data["dex_files"][0]["call_sites"][0]["target"]["method_name"] == "isDebuggerConnected"


def test_call_limit_is_explicit_and_indirect_invokes_are_unresolved():
    raw, _ = code_fixture(b"\x71\0\0\0\0\0" * 2 + b"\x0e\0")
    result = parse_calls(raw, Settings(_env_file=None, max_dex_findings=1))
    assert len(result["call_sites"]) == 1
    assert result["instruction_analysis"]["output_limited"]
    assert result["coverage"] == "partial"
    raw, _ = code_fixture(b"\xfc\0\0\0\0\0\x0e\0")
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["call_sites"] == []
    assert result["instruction_analysis"]["issues"][0]["code"] == "dex_indirect_invoke_unresolved"


def test_code_bounds_fail_before_decoding():
    raw, offset = code_fixture()
    raw = bytearray(raw)
    struct.pack_into("<I", raw, offset + 12, 0xFFFFFFFF)
    result = parse_calls(bytes(raw), Settings(_env_file=None))
    assert result["call_sites"] == []
    assert result["instruction_analysis"]["issues"][0]["code"] == "dex_code_bounds_invalid"


def test_empty_concrete_code_body_is_partial_not_success():
    raw, _ = code_fixture(b"")
    result = parse_calls(raw, Settings(_env_file=None))
    assert result["coverage"] == "partial"
    assert result["instruction_analysis"]["counts"]["bodies_decoded"] == 0
    assert result["instruction_analysis"]["issues"][0]["code"] == "dex_code_header_invalid"
