"""Evidence-preserving review leads; no intent, execution or evasion verdict."""

import hashlib
import json

VERSION = "1.0.0"
RULES = {
    "DEX.DYNAMIC_LOADING": (
        "dynamic_loading",
        "Plugins and application update frameworks can load code",
    ),
    "DEX.DEBUGGER_CHECK": (
        "debugger_check",
        "Diagnostics and development utilities can check debugger state",
    ),
    "DEX.REFLECTION": ("reflection", "Frameworks and compatibility code commonly use reflection"),
    "DEX.NATIVE_LOADING": (
        "native_loading",
        "Legitimate applications commonly load native libraries",
    ),
}
FORMATS = {
    "embedded_dex_candidate": "embedded_dex",
    "embedded_zip_candidate": "embedded_archive",
    "elf_candidate": "native_binary",
}


def review(dex, resources, sample_hash, settings):
    groups = {}
    limited = False

    def add(category, key, evidence, explanation):
        nonlocal limited
        signature = json.dumps([category, key], sort_keys=True)
        if signature not in groups:
            if len(groups) >= settings.max_review_findings:
                limited = True
                return
            groups[signature] = {
                "id": hashlib.sha256(
                    json.dumps([VERSION, sample_hash, category, key], sort_keys=True).encode()
                ).hexdigest(),
                "category": category,
                "subject": key,
                "requires_review": True,
                "benign_explanation": explanation,
                "evidence": [],
                "evidence_count": 0,
                "evidence_truncated": False,
                "_seen": set(),
            }
        group = groups[signature]
        identity = json.dumps(evidence, sort_keys=True)
        if identity in group["_seen"]:
            return
        group["_seen"].add(identity)
        group["evidence_count"] += 1
        if len(group["evidence"]) < settings.max_review_evidence:
            group["evidence"].append(evidence)
        else:
            group["evidence_truncated"] = limited = True

    for member in dex.get("dex_files", []):
        calls = member.get("call_sites", [])
        called = {call["target"]["method_index"] for call in calls}
        observations = [(call, call["target"], "decoded_invoke_instruction") for call in calls]
        observations += [
            (ref, ref, "method_identifier_reference")
            for ref in member.get("api_references", [])
            if ref["method_index"] not in called
        ]
        for observed, target, state in observations:
            if observed["rule_id"] not in RULES:
                continue
            category, explanation = RULES[observed["rule_id"]]
            subject = {
                key: target.get(key) for key in ("class_descriptor", "method_name", "descriptor")
            }
            add(
                category,
                subject,
                {
                    **observed,
                    "member": member["member"],
                    "sha256": member["sha256"],
                    "evidence_state": state,
                },
                explanation,
            )
    for item in resources.get("files", []):
        category = FORMATS.get(item.get("format"))
        if category:
            add(
                category,
                {"member": item["member"]},
                {
                    "member": item["member"],
                    "sha256": item["sha256"],
                    "format": item["format"],
                    "evidence_state": "file_header_candidate",
                },
                "Packaged plugins and native dependencies can be legitimate; "
                "headers alone do not validate a payload",
            )
    findings = []
    for key in sorted(groups):
        group = groups[key]
        group.pop("_seen")
        states = {item["evidence_state"] for item in group["evidence"]}
        group["strongest_evidence"] = (
            "decoded_invoke_instruction"
            if "decoded_invoke_instruction" in states
            else "method_identifier_reference"
            if "method_identifier_reference" in states
            else "file_header_candidate"
        )
        findings.append(group)
    complete = dex.get("coverage") == "call_sites_decoded" and resources.get("coverage") in {
        "selected_members_inspected",
        "no_selected_members",
    }
    return {
        "rule_version": VERSION,
        "findings": findings,
        "coverage": "partial" if limited or not complete else "selected_rules_applied",
        "source_coverage": {
            "dex": dex.get("coverage", "unavailable"),
            "resources": resources.get("coverage", "unavailable"),
        },
        "output_limited": limited,
        "not_evaluated": [
            "anti_emulation",
            "control_flow_obfuscation",
            "encrypted_payloads",
            "reflection_target_resolution",
            "runtime_loading",
            "native_code_behaviour",
        ],
        "limitations": [
            "Review leads are not proof of evasion, malicious intent or runtime execution",
            "Only the versioned API allowlist and selected resource headers are reviewed",
            "Decoded invokes may be unreachable; identifier references may be unused",
            "Embedded DEX/ZIP/ELF candidates are not recursively analyzed or executed",
            "Co-occurrence does not link a loader to a packaged file",
            "Empty findings do not establish absence of evasion or a clean application",
        ],
    }
