"""Private subprocess entry point. Configuration enters via stdin, not command strings."""

import json
import sys
from pathlib import Path

from godeep.analysis.static.archive import InvalidAPK
from godeep.integrations.analyzers.common import AdapterFailure
from godeep.integrations.analyzers.registry import adapter_function


def main():
    payload = json.loads(sys.stdin.read(16384))
    try:
        analyze = adapter_function(payload.get("adapter", "archive_inventory"))
        config = dict(payload["config"])
        runtime_keys = {
            "signature_verify": ("signer_java_path", "signer_jar_path", "signer_jar_sha256"),
            "threat_review": ("intel_feed_path", "intel_feed_sha256"),
            "risk_review": ("intel_feed_path", "intel_feed_sha256"),
        }
        for keys in runtime_keys.values():
            for key in keys:
                config.pop(key, None)
        for key in runtime_keys.get(payload.get("adapter"), ()):
            config[key] = payload.get("runtime", {}).get(key)
        result = analyze(
            Path(payload["original"]),
            Path(payload["snapshot"]),
            payload["expected_hash"],
            config,
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
