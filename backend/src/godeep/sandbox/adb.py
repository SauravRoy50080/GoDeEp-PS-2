"""Bounded loopback smart-socket ADB probes. No host process or server lifecycle."""

import re
import socket
import struct
import time
from contextlib import contextmanager

PROPERTIES = {
    "emulator_marker": "ro.kernel.qemu",
    "avd_name": "ro.boot.qemu.avd_name",
    "boot_completed": "sys.boot_completed",
    "api_level": "ro.build.version.sdk",
    "abi": "ro.product.cpu.abi",
}


class ProbeError(Exception):
    """Stable failure code only; peer-supplied diagnostics are not echoed."""


class AdbProbe:
    def __init__(self, profile):
        self.profile = profile
        self.deadline = time.monotonic() + profile.total_timeout_seconds

    def _remaining(self, deadline):
        remaining = min(deadline, self.deadline) - time.monotonic()
        if remaining <= 0:
            raise ProbeError("timeout")
        return remaining

    @contextmanager
    def _connection(self):
        deadline = min(self.deadline, time.monotonic() + self.profile.command_timeout_seconds)
        try:
            with socket.create_connection(
                ("127.0.0.1", self.profile.adb_server_port), timeout=self._remaining(deadline)
            ) as stream:
                yield stream, deadline
        except TimeoutError as exc:
            raise ProbeError("timeout") from exc
        except OSError as exc:
            raise ProbeError("connection_unavailable") from exc

    def _read(self, stream, deadline, size):
        result = bytearray()
        while len(result) < size:
            stream.settimeout(self._remaining(deadline))
            chunk = stream.recv(size - len(result))
            if not chunk:
                raise ProbeError("unexpected_eof")
            result.extend(chunk)
        return bytes(result)

    def _length(self, stream, deadline):
        value = self._read(stream, deadline, 4)
        if re.fullmatch(b"[0-9a-fA-F]{4}", value) is None:
            raise ProbeError("invalid_frame_length")
        size = int(value, 16)
        if size > self.profile.max_output_bytes:
            raise ProbeError("output_limit")
        return size

    def _service(self, stream, deadline, request):
        encoded = request.encode("ascii")
        stream.settimeout(self._remaining(deadline))
        stream.sendall(f"{len(encoded):04x}".encode("ascii") + encoded)
        status = self._read(stream, deadline, 4)
        if status == b"FAIL":
            size = self._length(stream, deadline)
            self._read(stream, deadline, size)
            raise ProbeError("adb_rejected")
        if status != b"OKAY":
            raise ProbeError("invalid_status")

    def host(self, key):
        # No arbitrary server services, target discovery, forwarding or lifecycle methods.
        requests = {
            "version": "host:version",
            "state": f"host-serial:{self.profile.emulator_serial}:get-state",
            "features": f"host-serial:{self.profile.emulator_serial}:features",
        }
        if key not in requests:
            raise ProbeError("unsupported_probe")
        with self._connection() as (stream, deadline):
            self._service(stream, deadline, requests[key])
            size = self._length(stream, deadline)
            raw = self._read(stream, deadline, size)
        try:
            return raw.decode("ascii").strip()
        except UnicodeError as exc:
            raise ProbeError("invalid_encoding") from exc

    def property(self, key):
        if key not in PROPERTIES:
            raise ProbeError("unsupported_probe")
        with self._connection() as (stream, deadline):
            self._service(stream, deadline, f"host:transport:{self.profile.emulator_serial}")
            self._service(stream, deadline, "shell,v2,raw:getprop " + PROPERTIES[key])
            output, total = bytearray(), 0
            for _ in range(256):
                channel, size = struct.unpack("<BI", self._read(stream, deadline, 5))
                if total + size > self.profile.max_output_bytes:
                    raise ProbeError("output_limit")
                if channel not in (1, 2, 3) or (channel == 3 and size != 1):
                    raise ProbeError("invalid_shell_packet")
                raw = self._read(stream, deadline, size)
                total += size
                if channel == 3:
                    if raw != b"\0":
                        raise ProbeError("remote_command_failed")
                    try:
                        return output.decode("ascii").strip()
                    except UnicodeError as exc:
                        raise ProbeError("invalid_encoding") from exc
                if channel == 2:
                    # Unexpected diagnostics cannot be mistaken for a valid property value.
                    if raw:
                        raise ProbeError("remote_stderr")
                else:
                    output.extend(raw)
            raise ProbeError("packet_limit")
