"""Authenticated catalog of implemented adapter capabilities, not malware coverage."""

from fastapi import APIRouter

from godeep.api.dependencies import CurrentUser
from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS

router = APIRouter(tags=["analysis adapters"])


@router.get("/analyzers")
def analyzers(user: CurrentUser):
    capabilities = {
        "dex_exception_flow": [
            "bounded_try_and_handler_tables",
            "checked_exception_boundaries",
            "conservative_exception_edges",
            "normal_flow_with_evidence_offsets",
        ],
        "dex_control_flow": [
            "bounded_normal_flow_blocks",
            "checked_branch_targets",
            "switch_case_edges",
        ],
        "dex_graph": [
            "bounded_invoke_operand_graph",
            "per_dex_method_nodes",
            "caller_target_offset_evidence",
        ],
        "library_review": [
            "declared_maven_advisory_matching",
            "pinned_feed_provenance",
            "unresolved_library_metadata",
        ],
        "risk_review": [
            "explained_static_priority",
            "versioned_uncalibrated_policy",
            "offline_indicator_matching",
        ],
        "evasion_review": [
            "static_loading_and_debugger_leads",
            "embedded_file_candidates",
            "evidence_strength_and_coverage",
        ],
        "threat_review": [
            "offline_indicator_matching",
            "feed_provenance",
            "combined_static_review",
        ],
        "resource_inventory": [
            "resource_inventory",
            "declared_library_metadata",
            "resource_url_candidates",
        ],
        "signature_verify": ["official_apksigner_verification", "bounded_tool_diagnostics"],
        "static_review": [
            "unified_static_findings",
            "permission_context",
            "grouped_network_candidates",
        ],
        "dex_calls": ["decoded_invoke_sites", "caller_method_and_offsets"],
        "dex_static": ["dex_method_identifier_review", "dex_string_network_candidates"],
        "archive_inventory": ["archive_metadata", "dex_and_native_path_inventory"],
        "android_static": [
            "binary_manifest",
            "permissions",
            "components",
            "manifest_review_rules",
            "certificate_metadata",
        ],
    }
    return [
        {
            "name": name,
            "version": version,
            "capabilities": capabilities[name],
            "apk_execution": False,
            "cryptographic_signature_verification": name == "signature_verify",
            "operator_tool_configuration_required": name
            in {"signature_verify", "threat_review", "risk_review", "library_review"},
            "malware_classification": False,
        }
        for name, version in ADAPTER_VERSIONS.items()
    ]
