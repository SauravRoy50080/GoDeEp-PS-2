"""Private subprocess entry point. Configuration enters via stdin, not command strings."""

import json
import sys
from pathlib import Path

from godeep.analysis.static.archive import InvalidAPK
from godeep.integrations.analyzers.archive_inventory import AdapterFailure, analyze


def main():
    payload = json.loads(sys.stdin.read(16384))
    try:
        result = analyze(
            Path(payload["original"]),
            Path(payload["snapshot"]),
            payload["expected_hash"],
            payload["config"],
        )
        Path(payload["output"]).write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        return 0
    except AdapterFailure as exc:
        code = str(exc)
    except InvalidAPK:
        code = "archive_validation_failed"
    except OSError:
        code = "evidence_unavailable"
    except Exception:
        code = "adapter_error"
    Path(payload["output"]).write_text(json.dumps({"error_code": code}), encoding="utf-8")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
