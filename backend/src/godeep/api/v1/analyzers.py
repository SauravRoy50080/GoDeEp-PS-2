"""Authenticated catalog of implemented adapter capabilities, not malware coverage."""

from fastapi import APIRouter

from godeep.api.dependencies import CurrentUser
from godeep.integrations.analyzers.registry import ADAPTER_VERSIONS

router = APIRouter(tags=["analysis adapters"])


@router.get("/analyzers")
def analyzers(user: CurrentUser):
    capabilities = {
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
            "cryptographic_signature_verification": False,
            "malware_classification": False,
        }
        for name, version in ADAPTER_VERSIONS.items()
    ]
