"""Read-only case-scoped comparisons of hash-verified completed observations."""

import json

from fastapi import HTTPException

from godeep.analysis.correlation.comparison import compare
from godeep.core.security import aware
from godeep.persistence.models import AnalysisJob, Sample, utc_now
from godeep.services.cases import require_case
from godeep.storage.artifacts import read_verified


def compare_jobs(factory, settings, case_id, user_id, left_id, right_id):
    with factory() as session:
        require_case(session, case_id, user_id)
        jobs, samples, results = [], [], []
        for job_id in (left_id, right_id):
            job = session.get(AnalysisJob, str(job_id))
            if job is None or job.case_id != case_id:
                raise HTTPException(404, "Analysis not found in this case")
            sample = session.get(Sample, job.sample_id)
            if sample is None or sample.case_id != case_id:
                raise HTTPException(404, "Analysis sample not found in this case")
            if job.status != "completed":
                raise HTTPException(409, "Comparison requires completed analyses")
            if job.adapter not in {"static_review", "threat_review"}:
                raise HTTPException(422, "Comparison supports static_review and threat_review runs")
            jobs.append(job)
            samples.append(sample)
        if (jobs[0].adapter, jobs[0].adapter_version) != (jobs[1].adapter, jobs[1].adapter_version):
            raise HTTPException(409, "Select the same adapter and version on both sides")
        for job, sample in zip(jobs, samples):
            raw = read_verified(
                settings.evidence_root, job.result_key, job.result_sha256, settings.max_result_bytes
            )
            try:
                data = json.loads(raw)
                if not isinstance(data, dict) or any(
                    data.get(key) != expected
                    for key, expected in (
                        ("schema_version", 1),
                        ("adapter", job.adapter),
                        ("adapter_version", job.adapter_version),
                        ("input_sha256", sample.sha256),
                    )
                ):
                    raise ValueError("Invalid source identity")
                if job.input_sha256 != sample.sha256:
                    raise ValueError("Invalid source input")
            except (ValueError, UnicodeError) as exc:
                raise HTTPException(409, "Analysis result identity is invalid") from exc
            results.append(data)
        try:
            document = compare(
                *results, settings, configurations_equal=jobs[0].config == jobs[1].config
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise HTTPException(409, "Source analysis structure is not comparable") from exc
        document.update(
            {
                "schema_version": 1,
                "case_id": case_id,
                "generated_at": utc_now().isoformat(),
                "same_input_sha256": samples[0].sha256 == samples[1].sha256,
            }
        )
        for label, job, sample in zip(("left", "right"), jobs, samples):
            document[label] = {
                "job_id": job.id,
                "sample_id": sample.id,
                "input_sha256": sample.sha256,
                "adapter": job.adapter,
                "adapter_version": job.adapter_version,
                "result_sha256": job.result_sha256,
                "completed_at": aware(job.finished_at).isoformat() if job.finished_at else None,
                "identity": results[0 if label == "left" else 1].get("manifest", {}).get("identity")
                if results[0 if label == "left" else 1].get("manifest")
                else None,
            }
        try:
            raw = json.dumps(document, sort_keys=True, allow_nan=False).encode("utf-8")
        except ValueError as exc:
            raise HTTPException(409, "Comparison cannot be represented as strict JSON") from exc
        if len(raw) > settings.max_comparison_bytes:
            raise HTTPException(413, "Comparison exceeds configured output bounds")
        return raw
