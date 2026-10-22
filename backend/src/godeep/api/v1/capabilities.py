"""Explicit availability for frontends; unavailable analysis never becomes a verdict."""

from fastapi import APIRouter

from godeep.api.dependencies import CurrentUser
from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS

router = APIRouter(tags=["backend capabilities"])


@router.get("/capabilities")
def capabilities(user: CurrentUser):
    return {
        "schema_version": 1,
        "static_adapters": ADAPTER_VERSIONS,
        "runtime": {
            "imported_traces": "available_collector_asserted",
            "passive_process_sampler": "implemented_live_compatibility_unverified",
            "isolated_apk_execution": "unavailable_lab_validation_required",
            "filesystem_network_sensitive_collectors": "external_traces_required",
        },
        "ml": {
            "production_inference": "unavailable",
            "reasons": [
                "labeled_apk_corpus_missing",
                "extractor_parity_unverified",
                "external_accuracy_and_calibration_unverified",
            ],
            "csv_research": "available_offline_with_strict_data_gates",
        },
        "intelligence": {
            "pinned_local_feed": "available",
            "misp_export_subset": "available_offline",
            "live_provider_sync": "unconfigured",
        },
        "reports": {
            "json_html": "available",
            "analyst_reviews": "available_append_only",
            "evidence_package": "available",
            "ed25519_signing": "offline_operator_key_required",
            "formal_organizational_signoff": "not_established",
        },
        "interpretation": "Capabilities describe implementation, not malware coverage or accuracy",
    }
