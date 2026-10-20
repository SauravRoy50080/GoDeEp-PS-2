"""Exact local intelligence matching with provenance, expiry and conflicting claims."""

import hashlib
import json
from datetime import UTC, datetime

from godeep.integrations.intelligence.local_feed import canonical, load_feed

VERSION = "1.0.0"


def enrich(candidates, settings, now=None):
    now = now or datetime.now(UTC)
    feed = load_feed(settings, now)
    index = feed.pop("index")
    groups = {}
    partial = False
    rejected = 0
    for candidate in candidates:
        try:
            key = (candidate["kind"], canonical(candidate["kind"], candidate["value"]))
        except (ValueError, UnicodeError):
            rejected += 1
            partial = True
            continue
        if key not in groups:
            if len(groups) >= settings.max_intel_candidates:
                partial = True
                continue
            groups[key] = {
                "id": hashlib.sha256(json.dumps(key).encode()).hexdigest(),
                "kind": key[0],
                "value": key[1],
                "evidence": [],
                "_seen": set(),
                "evidence_count": 0,
                "evidence_truncated": False,
            }
        item = groups[key]
        serialized = json.dumps(candidate["evidence"], sort_keys=True)
        if serialized not in item["_seen"]:
            item["_seen"].add(serialized)
            item["evidence_count"] += 1
            if len(item["evidence"]) < settings.max_review_evidence:
                item["evidence"].append(candidate["evidence"])
            else:
                item["evidence_truncated"] = partial = True
    results = []
    for key in sorted(groups):
        item = groups[key]
        item.pop("_seen")
        matches = index.get(key, []) if feed["status"] == "available" else []
        active = [
            record for record in matches if record.valid_until is None or record.valid_until > now
        ]
        expired_records = [
            record
            for record in matches
            if record.valid_until is not None and record.valid_until <= now
        ]
        expired = len(expired_records)
        assertions = {record.classification for record in active}
        item.update(
            {
                "lookup_status": "not_checked"
                if feed["status"] != "available"
                else "matched"
                if active
                else "expired_indicators_only"
                if expired
                else "no_match_in_local_feed",
                "matches": [
                    record.model_dump(mode="json")
                    for record in active[: settings.max_intel_matches]
                ],
                "active_match_count": len(active),
                "expired_match_count": expired,
                "matches_truncated": len(active) > settings.max_intel_matches,
                "classification_labels_differ": len(assertions) > 1,
                "feed_assertions_conflict": "benign" in assertions
                and bool(assertions & {"malicious", "suspicious"}),
                "expired_match_ids": [
                    record.id for record in expired_records[: settings.max_intel_matches]
                ],
                "requires_review": True,
            }
        )
        if item["matches_truncated"] or expired:
            partial = True
        results.append(item)
    return {
        "rule_version": VERSION,
        "feed": feed,
        "indicators": results,
        "coverage": "not_checked"
        if feed["status"] != "available"
        else "partial"
        if partial
        else "local_exact_matching_complete",
        "rejected_candidate_count": rejected,
        "summary": {
            "candidate_groups": len(results),
            "matched_groups": sum(item["active_match_count"] > 0 for item in results),
        },
        "limitations": [
            "Feed assertions are source claims, not independently verified malware verdicts",
            "No match means unknown within this local feed, not safe",
            "Domain matches are exact; parent/subdomain matches are not inferred",
            "Expired records are excluded; conflicting active source claims remain visible",
            "Static strings do not prove contacted destinations or data exfiltration",
            "Feed snapshots must be retained by operators for full-run reproduction",
        ],
    }
