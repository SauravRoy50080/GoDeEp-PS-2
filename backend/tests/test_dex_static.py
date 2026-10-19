"""Original table-level DEX fixtures; no executable APK or installability claim."""

import hashlib
import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest

from godeep.analysis.static.dex import network_candidates, parse_dex
from godeep.core.config import Settings
from godeep.integrations.analyzers.common import AdapterFailure
from godeep.workers.runner import run_once


def dex_fixture(extra=()):
    strings = ["Ldalvik/system/DexClassLoader;", "<init>", "V", "https://example.org/path", *extra]
    so = 112
    to = so + 4 * len(strings)
    po, mo = to + 4, to + 16
    data_start = mo + 8
    raw = bytearray(data_start)
    raw[:8] = b"dex\n035\0"
    struct.pack_into("<II", raw, 36, 112, 0x12345678)
    struct.pack_into("<II", raw, 56, len(strings), so)
    struct.pack_into("<II", raw, 64, 1, to)
    struct.pack_into("<II", raw, 72, 1, po)
    struct.pack_into("<II", raw, 88, 1, mo)
    struct.pack_into("<HHI", raw, mo, 0, 0, 1)
    for i, value in enumerate(strings):
        struct.pack_into("<I", raw, so + 4 * i, len(raw))
        units = len(value.encode("utf-16-le")) // 2
        while units >= 128:
            raw.append((units & 127) | 128)
            units >>= 7
        raw.append(units)
        raw.extend(value.encode("utf-8").replace(b"\0", b"\xc0\x80"))
        raw.append(0)
    struct.pack_into("<I", raw, 32, len(raw))
    struct.pack_into("<II", raw, 104, len(raw) - data_start, data_start)
    return bytes(raw)


def test_table_references_and_network_evidence():
    raw = dex_fixture(["192.0.2.1", "ordinary text", "Ljava/net/URL;"])
    result = parse_dex(raw, Settings(_env_file=None))
    lead = result["api_references"][0]
    assert lead["category"] == "dynamic_loading"
    assert lead["evidence_state"] == "method_identifier_reference"
    assert lead["byte_offset"] < len(raw)
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert {i["kind"] for i in result["network_candidates"]} == {"url", "domain", "ip"}
    assert result["full_dex_validation"] == "not_performed"
    assert network_candidates("Lcom/example/org;") == []
    assert network_candidates("https://[broken") == []


@pytest.mark.parametrize("offset,value", [(32, 1), (36, 120), (40, 0), (60, 999999), (68, 1)])
def test_invalid_header_and_table_offsets(offset, value):
    raw = bytearray(dex_fixture())
    struct.pack_into("<I", raw, offset, value)
    with pytest.raises(AdapterFailure, match="dex_parse_failed"):
        parse_dex(bytes(raw), Settings(_env_file=None))


def test_limits_and_unsupported_format():
    raw = dex_fixture()
    with pytest.raises(AdapterFailure, match="dex_limits_exceeded"):
        parse_dex(raw, Settings(_env_file=None, max_dex_identifiers=1))
    with pytest.raises(AdapterFailure, match="dex_string_invalid_or_over_limit"):
        parse_dex(raw, Settings(_env_file=None, max_dex_string_bytes=16))
    raw = raw[:4] + b"041" + raw[7:]
    with pytest.raises(AdapterFailure, match="dex_format_unsupported"):
        parse_dex(raw, Settings(_env_file=None))


def test_output_limit_and_modified_utf8():
    data = parse_dex(
        dex_fixture(["a\0b", "https://example.net"]), Settings(_env_file=None, max_dex_findings=1)
    )
    assert data["coverage"] == "partial_output_limit"
    assert len(data["network_candidates"]) == 1


@pytest.mark.parametrize("mode", ["multidex", "absent"])
def test_worker_pipeline_preserves_failed_member_coverage(intake, mode):
    client, app, _ = intake
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())
        if mode == "multidex":
            archive.writestr("classes.dex", dex_fixture())
            archive.writestr("classes2.dex", b"bad dex")
    case = client.post("/api/v1/cases", json={"name": "DEX investigation"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=output.getvalue(),
        headers={"X-Filename": "fixture.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201, sample.text
    response = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "dex_static"},
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["config"]["max_dex_files"] == 32
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["coverage"] == ("partial" if mode == "multidex" else "no_dex_found")
    if mode == "multidex":
        assert data["dex_files"][1]["error_code"] == "dex_parse_failed"
        assert data["dex_files"][0]["api_references"]
