"""Deterministic grouping and permission context; no risk or runtime verdicts."""

import hashlib
import json

VERSION = "1.0.0"
RELATED = {
    "DEX.SMS_SEND": ["android.permission.SEND_SMS"],
    "DEX.LOCATION_ACCESS": [
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
    ],
    "DEX.MEDIA_RECORDING": ["android.permission.RECORD_AUDIO", "android.permission.CAMERA"],
}


def stable_id(sample_hash, key):
    return hashlib.sha256(
        json.dumps([VERSION, sample_hash, key], sort_keys=True).encode()
    ).hexdigest()


def correlate(manifest, dex, sample_hash, settings):
    groups, candidates = {}, {}
    limited = False

    def group(key, rule, title, severity="low"):
        nonlocal limited
        if key not in groups:
            if len(groups) >= settings.max_review_findings:
                limited = True
                return None
            groups[key] = {
                "id": stable_id(sample_hash, key),
                "rule_id": rule,
                "rule_version": VERSION,
                "title": title,
                "severity": severity,
                "requires_review": True,
                "evidence": [],
                "_seen": set(),
                "evidence_count": 0,
                "evidence_truncated": False,
                "evidence_state": "static_indicator",
            }
        return groups[key]

    def evidence(item, value):
        nonlocal limited
        signature = json.dumps(value, sort_keys=True)
        if signature in item["_seen"]:
            return
        item["_seen"].add(signature)
        item["evidence_count"] += 1
        if len(item["evidence"]) < settings.max_review_evidence:
            item["evidence"].append(value)
        else:
            item["evidence_truncated"] = limited = True

    if manifest:
        for observed in manifest["findings"]:
            key = (observed["rule_id"], observed["evidence"]["selector"])
            item = group(key, observed["rule_id"], observed["title"], observed["severity"])
            if item is not None:
                evidence(item, {"kind": "manifest_declaration", **observed["evidence"]})
                item["observation_confidence"] = observed["confidence"]
    for member in dex.get("dex_files", []):
        source = {"member": member["member"], "sha256": member["sha256"]}
        calls = member.get("call_sites", [])
        called_ids = {call["target"]["method_index"] for call in calls}
        observations = [(call, call["target"], "decoded_invoke_instruction") for call in calls]
        observations += [
            (ref, ref, "method_identifier_reference")
            for ref in member.get("api_references", [])
            if ref["method_index"] not in called_ids
        ]
        for observed, target, state in observations:
            rule = observed["rule_id"]
            key = (rule, target["class_descriptor"], target["method_name"])
            item = group(
                key,
                rule,
                "Review API evidence: " + target["class_descriptor"] + "->" + target["method_name"],
            )
            if item is None:
                continue
            detail = {"kind": state, **source, **observed}
            evidence(item, detail)
            if state == "decoded_invoke_instruction":
                item["evidence_state"] = state
            elif item["evidence_state"] == "static_indicator":
                item["evidence_state"] = state
            item["observation_confidence"] = "high"
        for indicator in member.get("network_candidates", []):
            key = (indicator["kind"], indicator["value"])
            if key not in candidates:
                if len(candidates) >= settings.max_review_findings:
                    limited = True
                    continue
                candidates[key] = {
                    "id": stable_id(sample_hash, ("ioc", *key)),
                    "kind": key[0],
                    "value": key[1],
                    "evidence": [],
                    "_seen": set(),
                    "evidence_count": 0,
                    "evidence_truncated": False,
                    "reputation": "not_checked",
                    "evidence_state": "string_literal_candidate",
                }
            evidence(candidates[key], {**source, **indicator})
    findings = []
    for key in sorted(groups):
        item = groups[key]
        item.pop("_seen")
        names = RELATED.get(item["rule_id"], [])
        declarations = (
            [] if not manifest else [p for p in manifest["permissions"] if p["name"] in names]
        )
        item["permission_context"] = {
            "related_names": names,
            "declarations": declarations,
            "manifest_sha256": manifest["source"]["sha256"] if manifest else None,
            "status": "not_mapped"
            if not names
            else "manifest_unavailable"
            if not manifest
            else "related_declaration_observed"
            if declarations
            else "no_related_declaration_observed",
            "interpretation": "SDK applicability, grants and API mode unresolved",
        }
        item["confidence_scope"] = (
            "Static observation only; not execution, exploitability or maliciousness"
        )
        item["independent_confirmation"] = "not_established"
        findings.append(item)
    iocs = []
    for key in sorted(candidates):
        item = candidates[key]
        item.pop("_seen")
        iocs.append(item)
    return {
        "rule_version": VERSION,
        "findings": findings,
        "network_candidates": iocs,
        "coverage": "partial_output_limit" if limited else "available_observations_grouped",
        "summary": {
            "finding_groups": len(findings),
            "network_candidate_groups": len(iocs),
            "requires_analyst_review": True,
        },
        "limitations": [
            "Grouped evidence is not independent confirmation and never increases a risk score",
            "Permission co-occurrence is not proof of grant, abuse or data flow",
            "Absent permission context is not a confirmed missing-permission vulnerability",
            "No runtime behaviour, threat reputation or malware verdict is inferred",
        ],
    }
