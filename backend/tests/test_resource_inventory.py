"""Synthetic resource/library declarations and real worker evidence contracts."""

import hashlib
import io
import struct
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest

from godeep.analysis.static.resources import inspect_resources, properties
from godeep.core.config import Settings
from godeep.workers.runner import run_once

POLICY = (
    b'<network-security-config><base-config cleartextTrafficPermitted="true">'
    b'<trust-anchors><certificates src="user"/></trust-anchors></base-config>'
    b'<domain-config><domain includeSubdomains="true">example.org</domain>'
    b"</domain-config></network-security-config>"
)


def apk_members(members):

    output = io.BytesIO()

    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", binary_manifest())

        for name, value in members.items():
            archive.writestr(name, value)

    return output.getvalue()


def inspect(members, **config):

    with ZipFile(io.BytesIO(apk_members(members))) as archive:
        return inspect_resources(archive, Settings(_env_file=None, **config))


def test_declared_library_identity_and_policy_evidence():

    path = "META-INF/maven/org.example/example/pom.properties"

    raw = b"groupId=org.example\nartifactId=example\nversion=1.2.3\n"

    result = inspect(
        {path: raw, "META-INF/androidx.demo_demo.version": b"1.0.0", "res/xml/network.xml": POLICY}
    )

    lib = result["library_candidates"][0]

    assert lib["version"] == "1.2.3" and lib["path_identity_matches"]

    assert lib["sha256"] == hashlib.sha256(raw).hexdigest()

    assert not lib["identity_verified"] and lib["vulnerability_status"] == "not_queried"

    policy = next(f["xml"] for f in result["files"] if f["member"].endswith("network.xml"))

    assert {p["value"] for p in policy["declarations"]} == {"true", "user", "example.org"}

    assert policy["resource_reference_binding"] == "not_resolved"


@pytest.mark.parametrize(
    "raw", [b"groupId=a\ngroupId=b\n", b"version=${v}", b"groupId=a\\\nb", b"\xff"]
)
def test_unsupported_or_ambiguous_properties_are_not_guessed(raw):

    with pytest.raises(ValueError):
        properties(raw)


def test_mismatching_metadata_paths_are_explicit():

    result = inspect(
        {
            "META-INF/maven/wrong/path/pom.properties": (
                b"groupId=org.example\nartifactId=example\nversion=1.2"
            )
        }
    )

    assert not result["library_candidates"][0]["path_identity_matches"]

    assert result["coverage"] == "partial"


def test_text_and_binary_xml_urls_have_correct_evidence_locations():

    # Existing original fixture encoder accepts arbitrary XML roots.

    binary = binary_manifest('<config endpoint="https://example.org/api"/>')

    text = "\u00e9 prefix https://example.net/path".encode()

    result = inspect({"assets/config.txt": text, "res/xml/endpoint.xml": binary})

    candidate = next(
        c
        for c in result["network_candidates"]
        if c["kind"] == "url" and c["member"].endswith("txt")
    )

    assert candidate["byte_offset"] == text.index(b"https://")

    xml = next(
        c
        for c in result["network_candidates"]
        if c["kind"] == "url" and c["member"].endswith("xml")
    )

    assert xml["selector"] == "/config/@endpoint" and "byte_offset" not in xml

    assert xml["reputation"] == "not_checked"


def test_dtd_is_rejected_and_limits_remain_partial():

    xml = b'<!DOCTYPE config [<!ENTITY e SYSTEM "file:///private">]><config>&e;</config>'

    result = inspect({"res/xml/config.xml": xml})

    assert result["coverage"] == "partial" and result["files"][0]["coverage"] == "parse_failed"

    result = inspect({"assets/large": b"x" * 100}, max_resource_bytes=64)

    assert result["coverage"] == "partial" and result["skipped_count"] == 1

    result = inspect({"assets/a": b"a", "assets/b": b"b"}, max_resource_files=1)

    assert result["coverage"] == "partial" and len(result["files"]) == 1

    result = inspect(
        {"assets/a.txt": b"https://example.org https://example.net"}, max_resource_findings=1
    )

    assert result["coverage"] == "partial" and len(result["network_candidates"]) == 1


def test_embedded_magic_and_native_headers_not_based_only_on_names():

    elf = bytearray(64)

    elf[:6] = b"\x7fELF\x02\x01"

    struct.pack_into("<H", elf, 18, 183)

    result = inspect(
        {
            "assets/disguised.png": b"dex\n035\0fixture",
            "assets/data": b"PK\x03\x04zip",
            "lib/arm64-v8a/libdemo.so": bytes(elf),
        }
    )

    assert {f["format"] for f in result["files"]} == {
        "embedded_dex_candidate",
        "embedded_zip_candidate",
        "elf_candidate",
    }

    native = result["files"][-1]["elf_header"]

    assert native["bits"] == 64 and native["machine_id"] == 183

    assert native["abi_directory"] == "arm64-v8a"
    unscoped = inspect({"lib/demo.so": bytes(elf)})
    assert unscoped["files"][0]["elf_header"]["abi_directory"] is None

    assert inspect({})["coverage"] == "no_selected_members"


def test_resource_inventory_worker_and_case_scoping(intake):

    client, app, _ = intake

    case = client.post("/api/v1/cases", json={"name": "Resource review"}).json()["id"]

    raw = apk_members({"assets/config.json": b'{"url":"https://example.org"}'})

    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=raw,
        headers={"X-Filename": "resource.apk", "Content-Type": "application/octet-stream"},
    )

    assert sample.status_code == 201

    queued = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "resource_inventory"},
    )

    assert queued.status_code == 202, queued.text

    job = queued.json()

    assert job["config"]["max_resource_files"] == 128

    run_once(app.state.sessions, app.state.settings)

    base = f"/api/v1/cases/{case}/analyses/{job['id']}"

    assert client.get(base).json()["status"] == "completed"

    result = client.get(base + "/result").json()["data"]

    assert result["observations"]["network_candidates"][0]["member"] == "assets/config.json"

    other = client.post("/api/v1/cases", json={"name": "Other"}).json()["id"]

    assert client.get(f"/api/v1/cases/{other}/analyses/{job['id']}/result").status_code == 404
