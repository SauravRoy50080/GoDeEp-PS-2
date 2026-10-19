"""Explicit trusted adapter allowlist. No client-supplied module or shell command."""

from importlib import import_module

ADAPTER_VERSIONS = {
    "archive_inventory": "1.0.0",
    "android_static": "1.0.0",
    "dex_static": "1.0.0",
    "dex_calls": "1.0.1",
    "static_review": "1.0.1",
    "signature_verify": "1.0.0",
    "resource_inventory": "1.0.0",
}


def adapter_function(name: str):
    if name not in ADAPTER_VERSIONS:
        raise ValueError("Unregistered adapter")
    module = import_module(f"godeep.integrations.analyzers.{name}")
    if module.VERSION != ADAPTER_VERSIONS[name]:
        raise ValueError("Adapter registry version mismatch")
    return module.analyze
