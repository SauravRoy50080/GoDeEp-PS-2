"""Authenticated catalog of implemented adapter capabilities, not malware coverage."""

from fastapi import APIRouter

from godeep.api.dependencies import CurrentUser
from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS

router = APIRouter(tags=["analysis adapters"])


@router.get("/analyzers")
def analyzers(user: CurrentUser):
    capabilities = {
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
            "operator_tool_configuration_required": name == "signature_verify",
            "malware_classification": False,
        }
        for name, version in ADAPTER_VERSIONS.items()
    ]
