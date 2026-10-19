"""Bounded Windows tool execution with kill-on-close ownership of descendants."""

import ctypes
import os
import subprocess
import tempfile
import time
from ctypes import wintypes
from pathlib import Path


class ToolOwnershipError(Exception):
    pass


class WindowsJob:
    def __init__(self):
        if os.name != "nt":
            raise ToolOwnershipError("unsupported_platform")

        class Basic(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64),
                ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD),
                ("min_set", ctypes.c_size_t),
                ("max_set", ctypes.c_size_t),
                ("active_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class IO(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in (
                    "read_ops",
                    "write_ops",
                    "other_ops",
                    "read_bytes",
                    "write_bytes",
                    "other_bytes",
                )
            ]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("basic", Basic),
                ("io", IO),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        api.CreateJobObjectW.restype = wintypes.HANDLE
        api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        api.SetInformationJobObject.restype = wintypes.BOOL
        api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        api.AssignProcessToJobObject.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        self.api = api
        self.handle = api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ToolOwnershipError("job_creation_failed")
        limit = Extended()
        limit.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not api.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limit), ctypes.sizeof(limit)
        ):
            self.close()
            raise ToolOwnershipError("job_configuration_failed")

    def assign(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ToolOwnershipError("job_assignment_failed")

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def run_tool(argv, directory, timeout, max_output):
    """argv comes only from trusted operator configuration; no shell is invoked."""
    if os.name != "nt":
        return {"status": "unsupported_platform", "exit_code": None, "output": ""}
    environment = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("GODEEP_")
        and k.upper()
        not in {
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
            "PGPASSWORD",
            "PGPASSFILE",
        }
    }
    process, owner = None, None
    status = "exited"
    try:
        owner = WindowsJob()
        with tempfile.TemporaryFile(dir=Path(directory)) as output:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                env=environment,
                cwd=directory,
                creationflags=subprocess.CREATE_NO_WINDOW,
                close_fds=True,
            )
            try:
                owner.assign(process)
                deadline = time.monotonic() + timeout
                while process.poll() is None:
                    if os.fstat(output.fileno()).st_size > max_output:
                        status = "output_limit"
                        break
                    if time.monotonic() >= deadline:
                        status = "timeout"
                        break
                    time.sleep(0.05)
            finally:
                owner.close()  # Also runs when the adapter is killed: Windows closes its handle.
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            output.seek(0)
            raw = output.read(max_output + 1)
            if len(raw) > max_output:
                status = "output_limit"
            return {
                "status": status,
                "exit_code": process.returncode,
                "output": raw[:max_output].decode("utf-8", "replace"),
            }
    except (OSError, ToolOwnershipError):
        return {"status": "tool_error", "exit_code": None, "output": ""}
    finally:
        if owner is not None:
            owner.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
