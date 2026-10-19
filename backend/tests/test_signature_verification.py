"""Status separation, bounded real processes and optional official-tool integration."""

import hashlib
import io
import os
import struct
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zipfile import ZipFile

import pytest
from android_fixtures import binary_manifest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from godeep.analysis.static.verification import interpret_verification, verify_signature
from godeep.core.config import Settings
from godeep.workers.bounded_tool import run_tool
from godeep.workers.runner import run_once


def unsigned_apk():
    # Resource-ID map supplies the real Android minSdkVersion attribute ID.
    manifest = binary_manifest()
    pool_size = struct.unpack_from("<I", manifest, 12)[0]
    # Original binary fixture uses UTF-8 pool; locate minSdkVersion string index.
    from androguard.core.axml import AXMLParser, AXMLPrinter
    from loguru import logger

    logger.disable("androguard")

    parser = AXMLParser(manifest)
    names = [parser.sb.getString(i) for i in range(parser.sb.stringCount)]
    resource_ids = [0] * len(names)
    resource_ids[names.index("minSdkVersion")] = 0x0101020C
    block = struct.pack("<HHI", 0x180, 8, 8 + 4 * len(names))
    block += struct.pack("<" + "I" * len(names), *resource_ids)
    manifest = bytearray(manifest[: 8 + pool_size] + block + manifest[8 + pool_size :])
    struct.pack_into("<I", manifest, 4, len(manifest))
    offset = 8
    while offset < len(manifest):
        kind, header, size = struct.unpack_from("<HHI", manifest, offset)
        if kind == 0x102:
            attribute_start, attribute_size, count = struct.unpack_from(
                "<3H", manifest, offset + 24
            )
            for index in range(count):
                base = offset + header + attribute_start + index * attribute_size
                name_index = struct.unpack_from("<I", manifest, base + 4)[0]
                if names[name_index] in ("minSdkVersion", "targetSdkVersion"):
                    manifest[base + 15] = 0x10
                    struct.pack_into(
                        "<I",
                        manifest,
                        base + 16,
                        23 if names[name_index] == "minSdkVersion" else 33,
                    )
        offset += size
    assert AXMLPrinter(bytes(manifest)).is_valid()
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/original.txt", b"original payload")
    return output.getvalue()


@pytest.mark.parametrize(
    "code,text,status",
    [
        (0, "Verifies\nVerified using v2 scheme (APK Signature Scheme v2): true\n", "verified"),
        (1, "DOES NOT VERIFY\nERROR: digest mismatch", "verification_failed"),
        (1, "Exception in thread main", "tool_error"),
        (2, "Bad options", "tool_error"),
        (0, "Unexpected output", "tool_error"),
    ],
)
def test_verifier_status_interpretation(code, text, status):
    actual, schemes = interpret_verification(
        {"status": "exited", "exit_code": code, "output": text}
    )
    assert actual == status
    if status == "verified":
        assert schemes == {"v2": True}


def test_certificate_text_cannot_override_scheme_summary():
    status, schemes = interpret_verification(
        {
            "status": "exited",
            "exit_code": 0,
            "output": "Verifies\nVerified using v2 scheme (APK Signature Scheme v2): true\n"
            "Number of signers: 1\nSigner #1 certificate DN: injected\n"
            "Verified using v2 scheme (APK Signature Scheme v2): false\n",
        }
    )
    assert status == "verified" and schemes == {"v2": True}


def test_unconfigured_verifier_is_never_signature_failure(tmp_path):
    source = tmp_path / "input.apk"
    source.write_bytes(b"fixture")
    result = verify_signature(source, Settings(_env_file=None))
    assert result["status"] == "tool_unavailable"
    assert result["cryptographic_verification"] == "not_performed"


@pytest.mark.skipif(os.name != "nt", reason="Windows process ownership implementation")
def test_real_tool_timeout_and_output_bound(tmp_path):
    result = run_tool([sys.executable, "-c", "import time;time.sleep(20)"], tmp_path, 0.1, 1024)
    assert result["status"] == "timeout"
    result = run_tool([sys.executable, "-c", "print('x'*10000)"], tmp_path, 2, 1024)
    assert result["status"] == "output_limit" and len(result["output"]) == 1024
    result = run_tool([sys.executable, "-c", "print('done')"], tmp_path, 2, 1024)
    assert result["status"] == "exited" and result["exit_code"] == 0


@pytest.fixture
def official_tools():
    java = os.environ.get("GODEEP_TEST_SIGNER_JAVA")
    jar = os.environ.get("GODEEP_TEST_SIGNER_JAR")
    if not java or not jar:
        pytest.skip("Official tool integration requires explicit test Java and apksigner paths")
    java, jar = Path(java), Path(jar)
    assert java.is_absolute() and java.is_file() and jar.is_absolute() and jar.is_file()
    return java, jar


@pytest.fixture
def signed_fixture(tmp_path, official_tools):
    java, jar = official_tools
    unsigned = tmp_path / "unsigned.apk"
    unsigned.write_bytes(unsigned_apk())
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GoDeEp generated test signer")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private, hashes.SHA256())
    )
    key_path, cert_path = tmp_path / "key.pk8", tmp_path / "cert.der"
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    signed = tmp_path / "signed.apk"
    result = run_tool(
        [
            str(java),
            "-jar",
            str(jar),
            "sign",
            "--key",
            str(key_path),
            "--cert",
            str(cert_path),
            "--v1-signing-enabled",
            "true",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "false",
            "--out",
            str(signed),
            str(unsigned),
        ],
        tmp_path,
        20,
        65536,
    )
    assert result["status"] == "exited" and result["exit_code"] == 0, result
    settings = Settings(
        _env_file=None,
        signer_java_path=java,
        signer_jar_path=jar,
        signer_jar_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),
    )
    return unsigned, signed, settings


def test_official_verifier_accepts_signed_rejects_unsigned_and_tampered(signed_fixture):
    unsigned, signed, settings = signed_fixture
    result = verify_signature(signed, settings)
    assert result["status"] == "verified", result
    assert result["schemes"]["v2"]
    assert result["tool"]["version"] and result["tool"]["java_version"]
    result = verify_signature(unsigned, settings)
    assert result["status"] == "verification_failed", result
    data = signed.read_bytes()
    assert b"original payload" in data
    signed.write_bytes(data.replace(b"original payload", b"modified payload"))
    assert verify_signature(signed, settings)["status"] == "verification_failed"


def test_tool_provenance_mismatch_blocks_verification(signed_fixture):
    _, signed, settings = signed_fixture
    settings.signer_jar_sha256 = "0" * 64
    assert verify_signature(signed, settings)["status"] == "provenance_mismatch"


def test_signature_job_real_worker_keeps_operator_paths_private(intake, signed_fixture):
    client, app, _ = intake
    _, signed, config = signed_fixture
    app.state.settings.signer_java_path = config.signer_java_path
    app.state.settings.signer_jar_path = config.signer_jar_path
    app.state.settings.signer_jar_sha256 = config.signer_jar_sha256
    case = client.post("/api/v1/cases", json={"name": "Signature review"}).json()["id"]
    sample = client.post(
        f"/api/v1/cases/{case}/samples",
        content=signed.read_bytes(),
        headers={"X-Filename": "signed.apk", "Content-Type": "application/octet-stream"},
    )
    assert sample.status_code == 201, sample.text
    job = client.post(
        f"/api/v1/cases/{case}/analyses",
        json={"sample_id": sample.json()["id"], "adapter": "signature_verify"},
    ).json()
    assert "signer_java_path" not in job["config"] and "signer_jar_path" not in job["config"]
    run_once(app.state.sessions, app.state.settings)
    base = f"/api/v1/cases/{case}/analyses/{job['id']}"
    assert client.get(base).json()["status"] == "completed"
    data = client.get(base + "/result").json()["data"]
    assert data["coverage"] == "verified_in_tool_scope", data
    assert data["signature_verification"]["status"] == "verified"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object ownership")
def test_killing_adapter_owner_terminates_its_tool(tmp_path):
    import ctypes
    import subprocess
    import time
    from ctypes import wintypes

    pid_file = tmp_path / "tool-pid.txt"
    child = (
        "import os,time;from pathlib import Path;Path("
        + repr(str(pid_file))
        + ").write_text(str(os.getpid()));time.sleep(60)"
    )
    parent_code = (
        "from godeep.workers.bounded_tool import run_tool;"
        "run_tool(" + repr([sys.executable, "-c", child]) + "," + repr(str(tmp_path)) + ",50,1024)"
    )
    parent = subprocess.Popen(
        [sys.executable, "-c", parent_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.WaitForSingleObject.restype = wintypes.DWORD
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = None
    try:
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert pid_file.exists(), "Tool did not start"
        handle = api.OpenProcess(0x100001, False, int(pid_file.read_text()))
        assert handle
        parent.kill()
        parent.wait(timeout=5)
        assert api.WaitForSingleObject(handle, 5000) == 0
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if handle:
            if api.WaitForSingleObject(handle, 0) != 0:
                api.TerminateProcess(handle, 1)
            api.CloseHandle(handle)
