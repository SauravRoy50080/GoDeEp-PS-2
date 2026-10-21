"""Real loopback fake ADB, bounded framing/deadlines and operator-only CLI."""

import hashlib
import json
import socketserver
import struct
import threading
import time
from contextlib import contextmanager

import pytest
from pydantic import ValidationError

from godeep.sandbox.adb import AdbProbe, ProbeError
from godeep.sandbox.doctor import main, preflight
from godeep.sandbox.profile import SandboxProfile


def packet(channel, raw):
    return struct.pack("<BI", channel, len(raw)) + raw


def frame(raw):
    return b"OKAY" + f"{len(raw):04x}".encode() + raw


def profile(port=5038, **updates):
    return SandboxProfile.model_validate(
        {
            "schema_version": 1,
            "adb_server_port": port,
            "emulator_serial": "emulator-5554",
            "avd_name": "godeep_api35",
            "api_level": 35,
            "abi": "x86_64",
            **updates,
        }
    )


@contextmanager
def server(*, faults=None, values=None, delay=0):
    requests = []
    properties = {
        "ro.kernel.qemu": b"1",
        "ro.boot.qemu.avd_name": b"godeep_api35",
        "sys.boot_completed": b"1",
        "ro.build.version.sdk": b"35",
        "ro.product.cpu.abi": b"x86_64",
        **(values or {}),
    }

    class Handler(socketserver.BaseRequestHandler):
        def request_text(self):
            def read(size):
                raw = b""
                while len(raw) < size:
                    chunk = self.request.recv(size - len(raw))
                    if not chunk:
                        raise ConnectionError()
                    raw += chunk
                return raw

            size = int(read(4), 16)
            text = read(size).decode("ascii")
            requests.append(text)
            return text

        def handle(self):
            self.request.settimeout(2)
            try:
                query = self.request_text()
                if delay:
                    time.sleep(delay)
                if query in (faults or {}):
                    self.request.sendall(faults[query])
                    return
                if query.startswith("host:transport:"):
                    self.request.sendall(b"OKAY")
                    query = self.request_text()
                    if query in (faults or {}):
                        self.request.sendall(faults[query])
                    else:
                        value = properties[query.split("getprop ")[1]]
                        # Fragment the shell packet header and data over separate writes.
                        reply = b"OKAY" + packet(1, value + b"\n") + packet(3, b"\0")
                        for byte in reply:
                            self.request.sendall(bytes([byte]))
                else:
                    value = (
                        b"0029"
                        if query == "host:version"
                        else (b"shell_v2,cmd" if query.endswith(":features") else b"device")
                    )
                    self.request.sendall(frame(value))
            except (OSError, ConnectionError):
                pass

    class TCP(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with TCP(("127.0.0.1", 0), Handler) as listener:
        thread = threading.Thread(
            target=listener.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            yield listener.server_address[1], requests
        finally:
            listener.shutdown()
            thread.join(timeout=2)


def test_real_tcp_preflight_fixed_selected_target_and_no_execution():
    with server() as (port, requests):
        report = preflight(profile(port))
    assert report["status"] == "preflight_checks_passed"
    assert len(report["checks"]) == 8
    assert report["apk_execution"] == report["dynamic_capture"] == "not_performed"
    assert report["isolation"] == "not_verified"
    assert requests[:3] == [
        "host:version",
        "host-serial:emulator-5554:get-state",
        "host-serial:emulator-5554:features",
    ]
    assert len(requests) == 13
    assert all(
        query.startswith(
            (
                "host:version",
                "host-serial:emulator-5554:",
                "host:transport:emulator-5554",
                "shell,v2,raw:getprop ",
            )
        )
        for query in requests
    )
    assert not any(
        "install" in query or "kill" in query or "devices" in query for query in requests
    )


@pytest.mark.parametrize(
    "name,value,reason",
    [
        ("ro.kernel.qemu", b"0", "emulator_marker_missing"),
        ("ro.boot.qemu.avd_name", b"other", "avd_name_mismatch"),
        ("sys.boot_completed", b"0", "boot_incomplete"),
        ("ro.build.version.sdk", b"34", "api_level_mismatch"),
        ("ro.product.cpu.abi", b"arm64-v8a", "abi_mismatch"),
    ],
)
def test_property_mismatches_block_preflight(name, value, reason):
    with server(values={name: value}) as (port, _):
        result = preflight(profile(port))
    assert result["status"] == "blocked" and result["reason"] == reason
    assert result["checks"][-1]["status"] == "failed"


@pytest.mark.parametrize(
    "reply,reason",
    [
        (b"NOPE", "invalid_status"),
        (b"OKAYzzzz", "invalid_frame_length"),
        (b"OKAYffff", "output_limit"),
        (b"OKAY0004ab", "unexpected_eof"),
        (b"FAIL0007private", "adb_rejected"),
        (frame(b"bad"), "invalid_server_version"),
    ],
)
def test_bad_host_frames_are_bounded_and_diagnostics_not_echoed(reply, reason):
    with server(faults={"host:version": reply}) as (port, _):
        result = preflight(profile(port, max_output_bytes=64))
    assert result["reason"] == reason
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize(
    "reply,reason",
    [
        (packet(0, b""), "invalid_shell_packet"),
        (packet(3, b"\0" * 4), "invalid_shell_packet"),
        (packet(3, b"\1"), "remote_command_failed"),
        (packet(2, b"private") + packet(3, b"\0"), "remote_stderr"),
        (packet(1, b"1"), "unexpected_eof"),
        (packet(1, b"\xff") + packet(3, b"\0"), "invalid_encoding"),
        (packet(1, b"") * 256, "packet_limit"),
        (struct.pack("<BI", 1, 1000000000), "output_limit"),
    ],
)
def test_bad_shell_packets_never_pass_readiness(reply, reason):
    with server(faults={"shell,v2,raw:getprop ro.kernel.qemu": b"OKAY" + reply}) as (port, _):
        result = preflight(profile(port))
    assert result["reason"] == reason and result["status"] == "blocked"
    assert "private" not in json.dumps(result)


@pytest.mark.parametrize(
    "query,value,reason",
    [
        ("host-serial:emulator-5554:get-state", b"offline", "target_not_ready"),
        ("host-serial:emulator-5554:features", b"cmd", "shell_v2_unavailable"),
    ],
)
def test_target_or_protocol_failure_stops_property_probes(query, value, reason):
    with server(faults={query: frame(value)}) as (port, requests):
        result = preflight(profile(port))
    assert result["reason"] == reason
    assert not any(request.startswith("shell") for request in requests)


def test_command_and_total_deadlines():
    for limits in (
        {"command_timeout_seconds": 0.1},
        {"command_timeout_seconds": 1, "total_timeout_seconds": 0.1},
    ):
        with server(delay=0.2) as (port, _):
            started = time.monotonic()
            report = preflight(profile(port, **limits))
            elapsed = time.monotonic() - started
        assert report["reason"] == "timeout" and elapsed < 2


@pytest.mark.parametrize(
    "updates",
    [
        {"adb_server_port": 5037},
        {"adb_server_port": True},
        {"emulator_serial": "physical-device"},
        {"emulator_serial": "emulator-5555"},
        {"emulator_serial": "emulator-5554;id"},
        {"avd_name": "../device"},
        {"api_level": 23},
        {"schema_version": True},
        {"host": "example.org"},
        {"total_timeout_seconds": float("nan")},
        {"max_output_bytes": 1000000},
    ],
)
def test_invalid_or_ambiguous_profiles_are_rejected(updates):
    with pytest.raises(ValidationError):
        profile(**updates)


def test_unknown_probes_do_not_connect():
    probe = AdbProbe(profile())
    for action in (lambda: probe.host("devices"), lambda: probe.property("id;reboot")):
        with pytest.raises(ProbeError, match="unsupported_probe"):
            action()


def test_cli_no_profile_exact_utf8_hash_no_overwrite(tmp_path, capsys):
    output = tmp_path / "preflight.json"
    assert main(["--output", str(output)]) == 2
    captured = capsys.readouterr()
    raw = output.read_bytes()
    assert json.loads(raw)["status"] == "configuration_required"
    assert json.loads(captured.out) == json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() in captured.err
    assert main(["--output", str(output)]) == 2
    assert output.read_bytes() == raw
    assert "already exists" in capsys.readouterr().err


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"schema_version":true}',
        b"x" * 16385,
        b'{"schema_version":1,"schema_version":1}',
        b'{"x":NaN}',
    ],
)
def test_cli_invalid_profile_is_a_structured_failure(tmp_path, capsys, raw):
    source = tmp_path / "profile.json"
    source.write_bytes(raw)
    assert main(["--profile", str(source)]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "invalid_profile"


def test_cli_real_loopback_profile_provenance(tmp_path, capsys):
    source = tmp_path / "profile.json"
    with server() as (port, _):
        raw = profile(port).model_dump_json().encode()
        source.write_bytes(raw)
        assert main(["--profile", str(source)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["profile_sha256"] == hashlib.sha256(raw).hexdigest()
    assert report["status"] == "preflight_checks_passed"
