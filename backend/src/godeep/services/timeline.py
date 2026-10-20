"""Evidence-linked chronology of selected collector assertions, without causality."""

import json

from fastapi import HTTPException

from godeep.persistence.models import RuntimeCapture
from godeep.services.reports import require_sample
from godeep.storage.runtime import read_trace


def runtime_timeline(factory, settings, case_id, sample_id, user_id, query):
    with factory() as session:
        _, sample = require_sample(session, case_id, sample_id, user_id)
        sources, events, total_bytes = [], [], 0
        for capture_id in sorted(str(value) for value in query.capture_ids):
            capture = session.get(RuntimeCapture, capture_id)
            if capture is None or capture.case_id != case_id or capture.sample_id != sample_id:
                raise HTTPException(404, "Runtime capture not found for this sample")
            raw, trace = read_trace(
                settings.evidence_root, capture, sample.sha256, settings.max_runtime_capture_bytes
            )
            total_bytes += len(raw)
            if total_bytes > settings.max_timeline_source_bytes:
                raise HTTPException(413, "Selected timeline sources exceed configured bounds")
            sources.append(
                {
                    "capture_id": capture.id,
                    "artifact_sha256": capture.artifact_sha256,
                    "source_run_id": trace.source_run_id,
                    "collector": trace.collector.model_dump(),
                    "collection_status": trace.collection_status,
                    "coverage": trace.coverage.model_dump(),
                    "package_name": trace.package_name,
                    "environment": trace.environment,
                    "started_at": trace.started_at.isoformat(),
                    "ended_at": trace.ended_at.isoformat(),
                    "attribution": "collector_asserted_not_verified",
                    "isolation": "not_verified",
                }
            )
            for observed in trace.events:
                if query.kinds and observed.kind not in query.kinds:
                    continue
                if query.started_at is not None and observed.timestamp < query.started_at:
                    continue
                if query.ended_at is not None and observed.timestamp > query.ended_at:
                    continue
                events.append(
                    (
                        observed.timestamp,
                        capture.id,
                        str(observed.event_id),
                        {
                            "capture_id": capture.id,
                            "event": observed.model_dump(mode="json"),
                            "evidence": {
                                "artifact_sha256": capture.artifact_sha256,
                                "event_id": str(observed.event_id),
                            },
                        },
                    )
                )
        events.sort(key=lambda item: item[:3])
        document = {
            "schema_version": 1,
            "case_id": case_id,
            "sample_id": sample_id,
            "input_sha256": sample.sha256,
            "sources": sources,
            "items": [item[3] for item in events[query.offset : query.offset + query.limit]],
            "total": len(events),
            "limit": query.limit,
            "offset": query.offset,
            "ordering": "collector_timestamp_then_capture_id_then_event_id",
            "limitations": [
                "Collector timestamps and attribution are unverified; clocks may differ",
                "Ordering does not establish causality, execution or independent confirmation",
                "PID identity is local to each capture and is not merged across runs",
                "Repeated events across captures are retained as separate source observations",
                "Empty filtered results do not establish absence of activity",
                "Trace hashes are verified; original APK bytes are not re-read for this view",
                "Read-only view; no report, job, score or audit event is created",
            ],
        }
        raw = json.dumps(document, sort_keys=True, allow_nan=False).encode("utf-8")
        if len(raw) > settings.max_timeline_bytes:
            raise HTTPException(413, "Timeline response exceeds configured bounds")
        return raw
