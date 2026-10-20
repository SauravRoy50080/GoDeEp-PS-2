"""Semantic observation comparison; missing evidence is never a safety verdict."""

import json

from godeep.integrations.intelligence.local_feed import canonical

VERSION = "1.0.0"


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def project(data):
    categories = {
        name: {}
        for name in (
            "permissions",
            "components",
            "application_flags",
            "certificate_metadata",
            "api_findings",
            "network_candidates",
            "feed_assertions",
        )
    }
    dropped = 0

    def add(category, key, value, evidence):
        item = categories[category].setdefault(
            encoded(key), {"key": key, "values": {}, "evidence": {}}
        )
        item["values"][encoded(value)] = value
        item["evidence"][encoded(evidence)] = evidence

    manifest = data.get("manifest")
    if manifest:
        source = {"member": "AndroidManifest.xml", "sha256": manifest["source"]["sha256"]}
        for permission in manifest["permissions"]:
            key = {"name": permission["name"], "element": permission["element"]}
            value = {
                k: permission.get(k) for k in ("max_sdk_version_raw", "uses_permission_flags_raw")
            }
            add("permissions", key, value, {**source, "selector": permission["evidence_selector"]})
        for component in manifest["components"]:
            if not component.get("name"):
                dropped += 1
                continue
            key = {"type": component["type"], "name": component["name"]}
            value = {
                k: component.get(k)
                for k in (
                    "enabled_from_manifest",
                    "exported_raw",
                    "exported_api17_plus",
                    "exported_basis",
                    "permission_inherited",
                    "permission_resolution",
                    "read_permission",
                    "write_permission",
                    "target_activity",
                    "launcher",
                    "authorities_raw",
                )
            }
            filters = []
            for intent in component["intent_filters"]:
                filters.append(
                    {
                        "actions": sorted(set(intent["actions"]), key=encoded),
                        "categories": sorted(set(intent["categories"]), key=encoded),
                        "data": sorted(intent["data"], key=encoded),
                    }
                )
            value["intent_filters"] = sorted(filters, key=encoded)
            add("components", key, value, {**source, "selector": component["evidence_selector"]})
        for key, value in manifest["application"]["flags"].items():
            add(
                "application_flags",
                {"name": key},
                value,
                {**source, "selector": "/manifest/application/@android:" + key},
            )
    for certificate in data.get("signing", {}).get("certificates", []):
        add(
            "certificate_metadata",
            {"sha256": certificate["sha256"]},
            {"sha256": certificate["sha256"], "verification": "not_performed"},
            {"sources": certificate["sources"]},
        )
    for finding in data.get("review", {}).get("findings", []):
        if not finding["rule_id"].startswith("DEX.") or not finding["evidence"]:
            continue
        first = finding["evidence"][0]
        target = first.get("target", first)
        key = {
            "rule_id": finding["rule_id"],
            "class_descriptor": target.get("class_descriptor"),
            "method_name": target.get("method_name"),
        }
        declarations = finding.get("permission_context", {}).get("declarations", [])
        permissions = [
            {
                k: p.get(k)
                for k in ("name", "element", "max_sdk_version_raw", "uses_permission_flags_raw")
            }
            for p in declarations
        ]
        value = {
            "evidence_state": finding["evidence_state"],
            "severity": finding["severity"],
            "observed_evidence_count": finding["evidence_count"],
            "evidence_truncated": finding["evidence_truncated"],
            "permission_declarations": sorted(permissions, key=encoded),
        }
        for evidence in finding["evidence"]:
            add(
                "api_findings",
                key,
                value,
                {
                    k: evidence[k]
                    for k in ("member", "sha256", "selector", "byte_offset", "method_index")
                    if k in evidence
                },
            )
    network = list(data.get("review", {}).get("network_candidates", []))
    network += data.get("resources", {}).get("network_candidates", [])
    for indicator in network:
        try:
            key = {
                "kind": indicator["kind"],
                "value": canonical(indicator["kind"], indicator["value"]),
            }
        except (ValueError, UnicodeError):
            dropped += 1
            continue
        evidence_list = indicator.get("evidence", [indicator])
        if not evidence_list:
            dropped += 1
            continue
        for evidence in evidence_list:
            add(
                "network_candidates",
                key,
                key,
                {
                    k: evidence[k]
                    for k in ("member", "sha256", "selector", "byte_offset", "string_index")
                    if k in evidence
                },
            )
    for indicator in data.get("intelligence", {}).get("indicators", []):
        if not indicator.get("matches"):
            continue
        key = {"kind": indicator["kind"], "value": indicator["value"]}
        for record in indicator["matches"]:
            add(
                "feed_assertions",
                key,
                record,
                {
                    "feed_sha256": data["intelligence"]["feed"].get("feed_sha256"),
                    "feed_id": data["intelligence"]["feed"].get("feed_id"),
                },
            )
    for entries in categories.values():
        for item in entries.values():
            item["values"] = [item["values"][key] for key in sorted(item["values"])]
            item["evidence"] = [item["evidence"][key] for key in sorted(item["evidence"])]
    return categories, dropped


def category_coverage(data, category):
    coverage = data.get("coverage", {})
    manifest_ok = coverage.get("manifest", {}).get("status") == "parsed"
    if category in ("permissions", "components", "application_flags"):
        return "profile_complete" if manifest_ok else "incomplete"
    if category == "certificate_metadata":
        return (
            "metadata_only"
            if coverage.get("signing") == "metadata_extraction_only"
            else "incomplete"
        )
    if category == "api_findings":
        return (
            "profile_complete"
            if (
                manifest_ok
                and coverage.get("dex") == "call_sites_decoded"
                and coverage.get("correlation") == "available_observations_grouped"
            )
            else "incomplete"
        )
    if category == "feed_assertions":
        return (
            "local_feed_only"
            if coverage.get("intelligence") == "local_exact_matching_complete"
            else "not_available_or_incomplete"
        )
    resource_ok = "resources" not in data or coverage.get("resources") in {
        "selected_members_inspected",
        "no_selected_members",
    }
    return (
        "profile_complete"
        if (
            coverage.get("dex") == "call_sites_decoded"
            and resource_ok
            and coverage.get("correlation") == "available_observations_grouped"
        )
        else "incomplete"
    )


def compare(left, right, settings, *, configurations_equal=True):
    a, rejected_a = project(left)
    b, rejected_b = project(right)
    warnings = []
    if not configurations_equal:
        warnings.append("analysis_configurations_differ")
    for field in ("tool_versions", "component_versions"):
        if left.get(field) != right.get(field):
            warnings.append(field + "_differ")
    if left.get("intelligence", {}).get("feed", {}).get("feed_sha256") != right.get(
        "intelligence", {}
    ).get("feed", {}).get("feed_sha256"):
        warnings.append("intelligence_feed_digests_differ")
    if (left.get("manifest") or {}).get("sdk") != (right.get("manifest") or {}).get("sdk"):
        warnings.append("manifest_sdk_contexts_differ")
    if rejected_a or rejected_b:
        warnings.append("unresolved_projection_items")
    output = {}
    for name in a:
        left_keys, right_keys = set(a[name]), set(b[name])
        changed = sorted(
            key
            for key in left_keys & right_keys
            if a[name][key]["values"] != b[name][key]["values"]
        )
        left_only, right_only = sorted(left_keys - right_keys), sorted(right_keys - left_keys)
        budget = settings.max_comparison_items
        selected_left = [a[name][key] for key in left_only[:budget]]
        budget -= len(selected_left)
        selected_right = [b[name][key] for key in right_only[:budget]]
        budget -= len(selected_right)
        selected_changed = [
            {"key": a[name][key]["key"], "left": a[name][key], "right": b[name][key]}
            for key in changed[:budget]
        ]
        truncated = len(left_only) + len(right_only) + len(changed) > settings.max_comparison_items
        ca, cb = category_coverage(left, name), category_coverage(right, name)
        compatible = ca == cb and ca in ("profile_complete", "metadata_only", "local_feed_only")
        reliable = compatible and not warnings and not truncated
        output[name] = {
            "left_only": selected_left,
            "right_only": selected_right,
            "changed": selected_changed,
            "unchanged_count": len(left_keys & right_keys) - len(changed),
            "counts": {
                "left_only": len(left_only),
                "right_only": len(right_only),
                "changed": len(changed),
            },
            "output_truncated": truncated,
            "left_coverage": ca,
            "right_coverage": cb,
            "absence_interpretation": "absence_in_selected_analysis_profiles_only"
            if reliable
            else "not_established",
        }
    return {
        "comparison_version": VERSION,
        "categories": output,
        "warnings": warnings,
        "projection_rejected": {"left": rejected_a, "right": rejected_b},
        "limitations": [
            "Differences describe observations, not proven app behaviour changes",
            "Finding IDs, artifact hashes and evidence selectors are not used as semantic equality",
            "A limited or different analysis profile cannot establish absence",
            "Certificate fingerprints are metadata, not APK signature verification",
            "Feed assertions are source claims and can change independently of APK contents",
            "No risk-score change, malware verdict, execution or reachability is inferred",
        ],
    }
