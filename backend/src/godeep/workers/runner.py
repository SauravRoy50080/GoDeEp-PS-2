"""Separate polling worker with wall-clock bounds and conditional result publication.

A subprocess boundary is not a malware sandbox. Registered static adapters
read bounded manifest/certificate data. Dynamic analysis and OS-level isolation
are future work.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from godeep.core.config import Settings
from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS
from godeep.persistence.database import build_engine, session_factory
from godeep.persistence.models import Sample
from godeep.services.jobs import claim_job, expire_jobs, finish_job, is_running


def run_once(factory, settings):
    expire_jobs(factory)
    job = claim_job(factory)
    if job is None:
        return False
    if ADAPTER_VERSIONS.get(job.adapter) != job.adapter_version:
        finish_job(factory, job.id, job.claim_token, error_code="unsupported_adapter_version")
        return True
    root = settings.evidence_root.resolve()
    temporary = root / "worker-staging"
    result_path = None
    try:
        temporary.mkdir(parents=True, exist_ok=True)
        with factory() as session:
            sample = session.get(Sample, job.sample_id)
            original = (root / sample.storage_key).resolve()
            if not original.is_relative_to(root) or sample.case_id != job.case_id:
                raise ValueError("invalid evidence reference")
        with tempfile.TemporaryDirectory(prefix=job.id + "-", dir=temporary) as scratch:
            output = Path(scratch) / "result.json"
            payload = {
                "adapter": job.adapter,
                "original": str(original),
                "snapshot": str(Path(scratch) / "input.apk"),
                "expected_hash": job.input_sha256,
                "config": job.config,
                "output": str(output),
                "runtime": {
                    "signer_java_path": str(settings.signer_java_path)
                    if settings.signer_java_path
                    else None,
                    "signer_jar_path": str(settings.signer_jar_path)
                    if settings.signer_jar_path
                    else None,
                    "signer_jar_sha256": settings.signer_jar_sha256,
                }
                if job.adapter == "signature_verify"
                else {
                    "intel_feed_path": str(settings.intel_feed_path)
                    if settings.intel_feed_path
                    else None,
                    "intel_feed_sha256": settings.intel_feed_sha256,
                }
                if job.adapter == "threat_review"
                else {},
            }
            environment = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith("GODEEP_") and k not in {"PGPASSWORD", "PGPASSFILE"}
            }
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            process = subprocess.Popen(
                [sys.executable, "-m", "godeep.workers.adapter_runner"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                env=environment,
                creationflags=flags,
            )
            try:
                process.stdin.write(json.dumps(payload))
                process.stdin.close()
                deadline = time.monotonic() + job.config["job_timeout_seconds"]
                while process.poll() is None:
                    if not is_running(factory, job.id, job.claim_token):
                        process.kill()
                        return True
                    if time.monotonic() >= deadline:
                        process.kill()
                        finish_job(factory, job.id, job.claim_token, error_code="adapter_timeout")
                        return True
                    time.sleep(0.1)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            if not output.exists() or output.stat().st_size > settings.max_result_bytes:
                finish_job(factory, job.id, job.claim_token, error_code="invalid_adapter_output")
                return True
            raw = output.read_bytes()
            result = json.loads(raw)
            if process.returncode != 0:
                allowed = {
                    "dex_limits_exceeded",
                    "manifest_parse_failed",
                    "manifest_ambiguous",
                    "manifest_dtd_rejected",
                    "manifest_limits_exceeded",
                    "member_size_exceeded",
                    "input_integrity_mismatch",
                    "input_size_exceeded",
                    "adapter_error",
                    "archive_validation_failed",
                    "evidence_unavailable",
                }
                code = result.get("error_code")
                finish_job(
                    factory,
                    job.id,
                    job.claim_token,
                    error_code=code if code in allowed else "adapter_error",
                )
                return True
            if (
                result.get("schema_version") != 1
                or result.get("adapter") != job.adapter
                or result.get("adapter_version") != job.adapter_version
                or result.get("input_sha256") != job.input_sha256
            ):
                raise ValueError("invalid adapter result identity")
            key = f"analysis/{job.id}/{job.claim_token}.json"
            result_path = root / key
            result_path.parent.mkdir(parents=True, exist_ok=True)
            os.replace(output, result_path)
            if not finish_job(
                factory,
                job.id,
                job.claim_token,
                result_key=key,
                result_sha256=hashlib.sha256(raw).hexdigest(),
            ):
                result_path.unlink(missing_ok=True)
            return True
    except Exception:
        if result_path is not None:
            result_path.unlink(missing_ok=True)
        finish_job(factory, job.id, job.claim_token, error_code="worker_error")
        return True


def main():
    parser = argparse.ArgumentParser(description="GoDeEp static-analysis job worker")
    parser.add_argument("--once", action="store_true", help="Process at most one queued job")
    args = parser.parse_args()
    settings = Settings()
    engine = build_engine(settings.database_url.get_secret_value())
    factory = session_factory(engine)
    try:
        while True:
            processed = run_once(factory, settings)
            if args.once:
                break
            if not processed:
                time.sleep(settings.worker_poll_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
