"""Read-only exact IP co-occurrence within a verified combined report snapshot."""

import ipaddress
import json

from fastapi import HTTPException

from godeep.schemas.runtime_captures import RuntimeTrace
from godeep.services.reports import download_report

VERSION = "1.0.0"
SUPPORTED = {("static_review", "1.0.1"), ("threat_review", "1.0.0")}


def canonical_ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Scoped or invalid IP")
    return str(ipaddress.ip_address(value))


def correlate(document, settings, limit, offset):
    groups, sources = {}, []
    ignored, rejected, scanned = 0, 0, 0
    supported, captures = 0, 0

    def retain(address, side, evidence):
        if address not in groups:
            if len(groups) >= settings.max_network_correlation_groups:
                raise HTTPException(413, "Network correlation group budget exceeded")
            groups[address] = {
                "ip": address,
                "static_count": 0,
                "collector_count": 0,
                "static_evidence": [],
                "collector_evidence": [],
            }
        item = groups[address]
        item[side + "_count"] += 1
        if len(item[side + "_evidence"]) < settings.max_network_correlation_evidence:
            item[side + "_evidence"].append(evidence)

    for index, source in enumerate(document["analyses"]):
        adapter = (source["adapter"], source["adapter_version"])
        metadata = {
            "kind": "analysis",
            "job_id": source["job_id"],
            "result_sha256": source["result_sha256"],
            "adapter": adapter[0],
            "adapter_version": adapter[1],
            "snapshot_pointer": f"/analyses/{index}",
        }
        if adapter not in SUPPORTED:
            sources.append({**metadata, "status": "unsupported_adapter_version"})
            continue
        supported += 1
        data = source["data"]
        if any(
            data.get(key) != value
            for key, value in (
                ("schema_version", 1),
                ("adapter", adapter[0]),
                ("adapter_version", adapter[1]),
                ("input_sha256", document["sample"]["sha256"]),
            )
        ):
            raise ValueError("Analysis identity mismatch")
        sources.append(
            {
                **metadata,
                "status": "selected_ip_candidates_scanned",
                "source_coverage": data["coverage"],
                "source_limitations": data.get("limitations", []),
            }
        )
        candidate_lists = [
            (
                f"/analyses/{index}/data/dex/dex_files/{member_index}/network_candidates",
                member.get("network_candidates", []),
            )
            for member_index, member in enumerate(data["dex"]["dex_files"])
        ]
        if adapter[0] == "threat_review":
            candidate_lists.append(
                (
                    f"/analyses/{index}/data/resources/network_candidates",
                    data["resources"]["network_candidates"],
                )
            )
        for pointer, candidates in candidate_lists:
            for candidate_index, candidate in enumerate(candidates):
                scanned += 1
                if scanned > settings.max_network_correlation_candidates:
                    raise HTTPException(413, "Network correlation candidate budget exceeded")
                if candidate["kind"] != "ip":
                    ignored += 1
                    continue
                try:
                    address = canonical_ip(candidate["value"])
                except ValueError:
                    rejected += 1
                    continue
                retain(
                    address,
                    "static",
                    {
                        "job_id": source["job_id"],
                        "result_sha256": source["result_sha256"],
                        "snapshot_pointer": f"{pointer}/{candidate_index}",
                        "evidence_state": "static_string_candidate",
                    },
                )

    for index, source in enumerate(document.get("runtime_captures", [])):
        trace = RuntimeTrace.model_validate(source["data"])
        if (
            trace.input_sha256 != document["sample"]["sha256"]
            or trace.source_run_id != source["source_run_id"]
        ):
            raise ValueError("Capture identity mismatch")
        captures += 1
        sources.append(
            {
                "kind": "runtime_capture",
                "capture_id": source["capture_id"],
                "artifact_sha256": source["artifact_sha256"],
                "snapshot_pointer": f"/runtime_captures/{index}",
                "source_run_id": trace.source_run_id,
                "coverage": trace.coverage.model_dump(),
                "collection_status": trace.collection_status,
                "collector": trace.collector.model_dump(),
                "package_name": trace.package_name,
                "environment": trace.environment,
                "attribution": "collector_asserted_not_verified",
                "isolation": "not_verified",
            }
        )
        for event_index, event in enumerate(trace.events):
            if event.kind != "network":
                continue
            try:
                address = canonical_ip(str(event.destination_ip))
            except ValueError:
                rejected += 1
                continue
            retain(
                address,
                "collector",
                {
                    "capture_id": source["capture_id"],
                    "artifact_sha256": source["artifact_sha256"],
                    "snapshot_pointer": f"/runtime_captures/{index}/data/events/{event_index}",
                    "event_id": str(event.event_id),
                    "timestamp": event.timestamp.isoformat(),
                    "pid": event.pid,
                    "transport": event.transport,
                    "destination_port": event.destination_port,
                    "attribution": "collector_asserted_not_verified",
                },
            )
    if not supported or not captures:
        raise HTTPException(409, "Select a report with supported static review and runtime sources")
    ordered = sorted(
        groups,
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )
    counts = {
        "in_both_selected_sources": 0,
        "static_only_in_selection": 0,
        "collector_only_in_selection": 0,
    }
    evidence_limited = False
    for address in ordered:
        item = groups[address]
        state = (
            "in_both_selected_sources"
            if item["static_count"] and item["collector_count"]
            else "static_only_in_selection"
            if item["static_count"]
            else "collector_only_in_selection"
        )
        item["relationship"] = state
        counts[state] += 1
        item["evidence_limited"] = any(
            item[side + "_count"] > len(item[side + "_evidence"])
            for side in ("static", "collector")
        )
        evidence_limited |= item["evidence_limited"]
    return {
        "schema_version": 1,
        "correlation_version": VERSION,
        "report_id": document["report_id"],
        "case_id": document["case"]["id"],
        "sample_id": document["sample"]["id"],
        "input_sha256": document["sample"]["sha256"],
        "sources": sources,
        "summary": counts,
        "total": len(groups),
        "items": [groups[address] for address in ordered[offset : offset + limit]],
        "limit": limit,
        "offset": offset,
        "non_ip_candidates_skipped": ignored,
        "invalid_or_scoped_ips_skipped": rejected,
        "evidence_limited": evidence_limited,
        "view_scope": "selected_supported_sources_only",
        "matching_basis": "exact_canonical_ip_from_emitted_static_candidates_and_collector_events",
        "limitations": [
            "Relationships describe selected snapshot records, not independent confirmation",
            "Collector attribution, package identity, clocks and isolation are unverified",
            "Static strings do not prove reachable code, contact, malicious intent or exfiltration",
            "Only emitted IP candidates are compared; no DNS, hostname or URL lookup is performed",
            "IP matches ignore port and transport; event references preserve those fields",
            "IPv4-mapped IPv6 and IPv4 remain distinct; scoped IP addresses are excluded",
            "Static and collector source limits remain; unmatched means absent in selection only",
            "Duplicate observations and overlapping analyzers are retained, not independent votes",
            "Pointers refer to normalized report JSON; hashes identify original trace bytes",
            "Original and source artifacts were checked at snapshot creation, not re-read here",
            "Read-only derived view; no report, audit, model inference or risk score is created",
        ],
    }


def network_correlation(factory, settings, case_id, sample_id, report_id, user_id, limit, offset):
    report, raw = download_report(factory, settings, case_id, sample_id, report_id, user_id)
    try:
        document = json.loads(raw)
        if (
            any(
                document.get(key) != value
                for key, value in (
                    ("report_id", report.id),
                    ("schema_version", report.schema_version),
                    ("report_type", "investigation_analysis_snapshot"),
                )
            )
            or report.schema_version != 2
        ):
            raise ValueError("Combined snapshot required")
        if (
            document["case"]["id"] != case_id
            or document["sample"]["id"] != sample_id
            or document["sample"]["sha256"] != report.input_sha256
        ):
            raise ValueError("Snapshot identity mismatch")
        if not 1 <= len(document["analyses"]) + len(document.get("runtime_captures", [])) <= 20:
            raise ValueError("Source count invalid")
        result = correlate(document, settings, limit, offset)
        result["source_report_sha256"] = report.artifact_sha256
        encoded = json.dumps(result, sort_keys=True, allow_nan=False).encode("utf-8")
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise HTTPException(409, "Report snapshot is not valid for network correlation") from exc
    if len(encoded) > settings.max_network_correlation_bytes:
        raise HTTPException(413, "Network correlation response exceeds configured bounds")
    return encoded
