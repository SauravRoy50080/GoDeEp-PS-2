"""Exact library declaration matching; no packaged-code or exploitability claim."""

from datetime import UTC, datetime

from godeep.integrations.intelligence.library_feed import load_library_feed

VERSION = "1.0.0"


def review_libraries(resources, settings, now=None):
    now = now or datetime.now(UTC)
    feed = load_library_feed(settings, now)
    index = feed.pop("index")
    groups, unresolved = {}, []
    partial = resources.get("coverage") not in {"selected_members_inspected", "no_selected_members"}
    for item in resources.get("library_candidates", []):
        if item.get("kind") != "maven_properties" or item.get("path_identity_matches") is not True:
            unresolved.append(
                {
                    "member": item["member"],
                    "sha256": item["sha256"],
                    "reason": "missing_or_conflicting_maven_identity",
                }
            )
            partial = True
            continue
        key = (item["groupId"], item["artifactId"], item["version"])
        group = groups.setdefault(
            key,
            {
                "group_id": key[0],
                "artifact_id": key[1],
                "declared_version": key[2],
                "evidence": [],
                "evidence_count": 0,
                "evidence_truncated": False,
                "_seen": set(),
            },
        )
        evidence_key = (item["member"], item["sha256"])
        if evidence_key not in group["_seen"]:
            group["_seen"].add(evidence_key)
            group["evidence_count"] += 1
            if len(group["evidence"]) < settings.max_review_evidence:
                group["evidence"].append(
                    {
                        "member": item["member"],
                        "sha256": item["sha256"],
                        "evidence_state": "declared_metadata",
                    }
                )
            else:
                group["evidence_truncated"] = partial = True
    output = []
    for key in sorted(groups):
        group = groups[key]
        group.pop("_seen")
        group["evidence"].sort(key=lambda value: (value["member"], value["sha256"]))
        records = index.get(key, []) if feed["status"] == "available" else []
        active = [
            record
            for record in records
            if not record.withdrawn and (record.valid_until is None or record.valid_until > now)
        ]
        withdrawn = sum(record.withdrawn for record in records)
        expired = sum(
            not record.withdrawn and record.valid_until is not None and record.valid_until <= now
            for record in records
        )
        labels = {record.assertion for record in active}
        retained = active[: settings.max_library_matches]
        limited = len(active) > len(retained)
        group.update(
            {
                "lookup_status": "not_checked"
                if feed["status"] != "available"
                else "matched_source_claims"
                if active
                else "excluded_claims_only"
                if records
                else "no_exact_match_in_local_feed",
                "matches": [
                    {
                        "id": entry.id,
                        "assertion": entry.assertion,
                        "title": entry.title,
                        "reference": str(entry.reference) if entry.reference else None,
                        "valid_until": entry.valid_until.isoformat() if entry.valid_until else None,
                    }
                    for entry in retained
                ],
                "active_match_count": len(active),
                "withdrawn_match_count": withdrawn,
                "expired_match_count": expired,
                "matches_truncated": limited,
                "source_claims_conflict": labels == {"affected", "not_affected"},
                "identity_verified": False,
                "requires_review": True,
            }
        )
        partial = partial or limited or bool(expired) or bool(withdrawn)
        output.append(group)
    return {
        "rule_version": VERSION,
        "feed": feed,
        "libraries": output,
        "unresolved": unresolved,
        "coverage": "not_checked"
        if feed["status"] != "available"
        else "partial"
        if partial
        else "local_exact_declaration_matching_complete",
        "limitations": [
            "Matches describe source claims about metadata, not verified packaged vulnerable code",
            "No exact match means unknown in this feed, not safe",
            "Version ranges, aliases, transitive dependencies and reachability are unresolved",
            "Coordinates and version strings match exactly without case folding or normalization",
            "Path conflicts and standalone version markers are not guessed",
            "Expired/withdrawn claims are excluded and conflicts remain visible",
            "No risk score, malware verdict, exploitability or network contact is inferred",
        ],
    }
