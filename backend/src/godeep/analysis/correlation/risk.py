"""Versioned, uncalibrated analyst-priority policy over static observations."""

VERSION = "1.0.0"
# Maximum once per rule, regardless of evidence multiplicity or API overloads.
WEIGHTS = {
    "MANIFEST.DEBUGGABLE": ("manifest", 10),
    "MANIFEST.CLEARTEXT_DECLARED": ("manifest", 10),
    "MANIFEST.BACKUP_DECLARED": ("manifest", 5),
    "MANIFEST.EXPORTED_REVIEW": ("manifest", 5),
    "DEX.DYNAMIC_LOADING": ("api", 10),
    "DEX.DEBUGGER_CHECK": ("api", 5),
    "DEX.REFLECTION": ("api", 3),
    "DEX.NATIVE_LOADING": ("api", 3),
    "DEX.PROCESS_EXECUTION": ("api", 8),
    "DEX.SMS_SEND": ("api", 8),
    "DEX.LOCATION_ACCESS": ("api", 4),
    "DEX.MEDIA_RECORDING": ("api", 4),
}
CAPS = {"manifest": 25, "api": 35, "intelligence": 40}


def prioritize(result):
    groups = {}
    excluded = []
    for finding in result.get("review", {}).get("findings", []):
        rule = finding["rule_id"]
        if rule not in WEIGHTS:
            continue
        category, base = WEIGHTS[rule]
        state = finding.get("evidence_state")
        if not finding.get("evidence"):
            continue
        if category == "api":
            # Integer quarter weight for identifier-only leads; no claim of execution.
            points = (
                base
                if state == "decoded_invoke_instruction"
                else max(1, base // 4)
                if state == "method_identifier_reference"
                else 0
            )
        else:
            points = base if state == "static_indicator" else 0
        if not points:
            continue
        item = groups.setdefault(
            rule,
            {
                "category": category,
                "rule_id": rule,
                "requested_points": 0,
                "source_finding_ids": set(),
                "reason": "One contribution per allowlisted rule; repeated evidence adds no points",
            },
        )
        item["requested_points"] = max(item["requested_points"], points)
        item["source_finding_ids"].add(finding["id"])
    intelligence = result.get("intelligence", {})
    feed = intelligence.get("feed", {})
    best = 0
    matched = []
    for index, indicator in enumerate(intelligence.get("indicators", [])):
        claims = indicator.get("matches", [])
        labels = {claim.get("classification") for claim in claims}
        if indicator.get("feed_assertions_conflict") or (
            "benign" in labels and bool(labels & {"suspicious", "malicious"})
        ):
            excluded.append({"indicator_index": index, "reason": "conflicting_source_claims"})
            continue
        if feed.get("status") != "available" or indicator.get("lookup_status") != "matched":
            continue
        points = 40 if "malicious" in labels else 20 if "suspicious" in labels else 0
        if points:
            best = max(best, points)
            matched.append(
                {
                    "indicator_index": index,
                    "kind": indicator["kind"],
                    "value": indicator["value"],
                    "record_ids": sorted({claim["id"] for claim in claims}),
                }
            )
    if best:
        groups["INTEL.SOURCE_ASSERTION"] = {
            "category": "intelligence",
            "rule_id": "INTEL.SOURCE_ASSERTION",
            "requested_points": best,
            "source_finding_ids": set(),
            "indicator_references": matched,
            "feed_sha256": feed.get("feed_sha256"),
            "reason": "Maximum non-conflicting source assertion; matches are not independent votes",
        }
    totals = dict.fromkeys(CAPS, 0)
    contributions = []
    for rule in sorted(groups):
        item = groups[rule]
        category = item["category"]
        item["awarded_points"] = min(item["requested_points"], CAPS[category] - totals[category])
        totals[category] += item["awarded_points"]
        item["source_finding_ids"] = sorted(item["source_finding_ids"])
        contributions.append(item)
    score = sum(totals.values())
    gaps = ["dynamic_not_analyzed", "policy_not_calibrated", "native_behaviour_not_analyzed"]
    coverage = result.get("coverage", {})
    if coverage.get("manifest", {}).get("status") != "parsed":
        gaps.append("manifest_incomplete")
    if coverage.get("dex") != "call_sites_decoded":
        gaps.append("dex_incomplete")
    if coverage.get("correlation") != "available_observations_grouped":
        gaps.append("grouping_incomplete")
    if coverage.get("resources") not in {"selected_members_inspected", "no_selected_members"}:
        gaps.append("resources_incomplete")
    if intelligence.get("coverage") != "local_exact_matching_complete":
        gaps.append("intelligence_unavailable_or_partial")
    return {
        "policy_version": VERSION,
        "score": score,
        "scale": {"minimum": 0, "maximum": 100},
        "meaning": "analyst_review_priority_only",
        "priority": "high" if score >= 50 else "elevated" if score >= 20 else "routine",
        "thresholds": {"elevated": 20, "high": 50},
        "calibration": "not_calibrated",
        "category_caps": CAPS.copy(),
        "category_totals": totals,
        "contributions": contributions,
        "excluded_intelligence": excluded,
        "coverage_gaps": gaps,
        "assessment_complete": False,
        "limitations": [
            "Score is an operator-designed heuristic, not a probability or malware verdict",
            "Zero means no scored observations in this policy, not safe or clean",
            "Permission declarations, certificate metadata and network strings alone add no points",
            "Missing evidence never subtracts points; coverage gaps must be reviewed separately",
            "Legitimate frameworks and applications can trigger these rules",
            "Category caps and thresholds are uncalibrated and require dataset evaluation",
        ],
    }
