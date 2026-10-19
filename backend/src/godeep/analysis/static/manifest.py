"""Bounded Android manifest decoding and conservative manifest-only review rules."""

import hashlib
import struct

from lxml import etree

from godeep.integrations.analyzers.common import AdapterFailure

ANDROID = "{http://schemas.android.com/apk/res/android}"
RULE_VERSION = "1.0.0"
SENSITIVE = {
    "READ_SMS": "sms",
    "RECEIVE_SMS": "sms",
    "SEND_SMS": "sms",
    "READ_CONTACTS": "contacts",
    "READ_CALL_LOG": "call_logs",
    "RECORD_AUDIO": "microphone",
    "CAMERA": "camera",
    "ACCESS_FINE_LOCATION": "location",
    "ACCESS_BACKGROUND_LOCATION": "location",
    "REQUEST_INSTALL_PACKAGES": "package_installation",
    "SYSTEM_ALERT_WINDOW": "overlay",
    "QUERY_ALL_PACKAGES": "package_visibility",
}


def attr(node, name):
    return node.get(ANDROID + name) if node is not None else None


def boolean(value):
    return (
        {"true": True, "false": False, "1": True, "0": False}.get(str(value).lower())
        if value is not None
        else None
    )


def integer(value):
    try:
        parsed = int(value, 16) if value.startswith("0x") else int(value)
        return parsed if parsed >= 1 else None
    except (ValueError, TypeError, AttributeError):
        return None


def preflight_axml(raw: bytes, max_nodes: int):
    if len(raw) < 8:
        raise AdapterFailure("manifest_parse_failed")
    kind, header, total = struct.unpack_from("<HHI", raw)
    if kind != 3 or header != 8 or total != len(raw):
        raise AdapterFailure("manifest_parse_failed")
    offset, count = 8, 0
    while offset < len(raw):
        if offset + 8 > len(raw):
            raise AdapterFailure("manifest_parse_failed")
        kind, header, size = struct.unpack_from("<HHI", raw, offset)
        if header < 8 or size < header or offset + size > len(raw):
            raise AdapterFailure("manifest_parse_failed")
        if kind == 1:
            if header < 28:
                raise AdapterFailure("manifest_parse_failed")
            strings, styles, _, start, _ = struct.unpack_from("<5I", raw, offset + 8)
            if (
                strings + styles > max_nodes * 8
                or start > size
                or start < header + 4 * (strings + styles)
            ):
                raise AdapterFailure("manifest_limits_exceeded")
        offset += size
        count += 1
        if count > max_nodes * 4:
            raise AdapterFailure("manifest_limits_exceeded")


def decode_manifest(raw: bytes, settings):
    anomalies = False
    if raw[:2] == b"\x03\x00":
        from androguard.core.axml import AXMLPrinter
        from loguru import logger

        logger.disable("androguard")
        preflight_axml(raw, settings.max_manifest_nodes)
        printer = AXMLPrinter(raw)
        if not printer.is_valid():
            raise AdapterFailure("manifest_parse_failed")
        node, format_name = printer.get_xml_obj(), "binary_axml"
        anomalies = printer.is_packed()
    else:
        parser = etree.XMLParser(
            resolve_entities=False, load_dtd=False, no_network=True, huge_tree=False, recover=False
        )
        node = etree.fromstring(raw, parser=parser)
        if node.getroottree().docinfo.doctype:
            raise AdapterFailure("manifest_dtd_rejected")
        format_name = "text_xml"
    if node is None or node.tag != "manifest" or not node.get("package"):
        raise AdapterFailure("manifest_parse_failed")
    nodes = list(node.iter())
    if len(nodes) > settings.max_manifest_nodes:
        raise AdapterFailure("manifest_limits_exceeded")
    if any(len(value) > 8192 for element in nodes for value in element.attrib.values()):
        raise AdapterFailure("manifest_limits_exceeded")
    return node, format_name, anomalies


def full_name(name, package):
    if not name or name.startswith(("@", "?")):
        return None
    return package + name if name.startswith(".") else name if "." in name else package + "." + name


def parse_manifest(raw: bytes, settings):
    try:
        root, format_name, anomalies = decode_manifest(raw, settings)
    except AdapterFailure:
        raise
    except Exception as exc:
        raise AdapterFailure("manifest_parse_failed") from exc
    if len(root.findall("application")) != 1 or len(root.findall("uses-sdk")) > 1:
        raise AdapterFailure("manifest_ambiguous")
    app, sdk = root.find("application"), root.find("uses-sdk")
    min_raw, target_raw = attr(sdk, "minSdkVersion"), attr(sdk, "targetSdkVersion")
    minimum = integer(min_raw) if min_raw is not None else 1
    target = integer(target_raw) if target_raw is not None else minimum
    package = root.get("package")
    app_enabled = boolean(attr(app, "enabled")) if attr(app, "enabled") is not None else True
    app_permission = attr(app, "permission")
    findings = []
    digest = hashlib.sha256(raw).hexdigest()

    def finding(rule, title, selector, observed, severity="low"):
        findings.append(
            {
                "rule_id": rule,
                "rule_version": RULE_VERSION,
                "severity": severity,
                "title": title,
                "evidence_state": "static_indicator",
                "requires_review": True,
                "confidence": "low" if anomalies else "high",
                "confidence_scope": "manifest observation, not exploitability or maliciousness",
                "evidence": {
                    "member": "AndroidManifest.xml",
                    "sha256": digest,
                    "selector": selector,
                    "observed": observed,
                },
            }
        )

    app_flags = {
        name: {"raw": attr(app, name), "declared": boolean(attr(app, name))}
        for name in [
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "testOnly",
            "requestLegacyExternalStorage",
        ]
    }
    if app_flags["debuggable"]["declared"] is True:
        finding(
            "MANIFEST.DEBUGGABLE",
            "Application explicitly declares debugging enabled",
            "/manifest/application/@android:debuggable",
            "true",
            "medium",
        )
    if app_flags["usesCleartextTraffic"]["declared"] is True:
        finding(
            "MANIFEST.CLEARTEXT_DECLARED",
            "Manifest permits cleartext; network policy needs review",
            "/manifest/application/@android:usesCleartextTraffic",
            "true",
        )
    if app_flags["allowBackup"]["declared"] is True:
        finding(
            "MANIFEST.BACKUP_DECLARED",
            "Backup enabled in manifest; backup rules need review",
            "/manifest/application/@android:allowBackup",
            "true",
        )
    permissions = []
    for tag in ["uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"]:
        for index, item in enumerate(root.findall(tag), 1):
            name = attr(item, "name")
            permissions.append(
                {
                    "name": name,
                    "element": tag,
                    "max_sdk_version_raw": attr(item, "maxSdkVersion"),
                    "uses_permission_flags_raw": attr(item, "usesPermissionFlags"),
                    "capability_review": SENSITIVE.get(name.removeprefix("android.permission."))
                    if name and name.startswith("android.permission.")
                    else None,
                    "evidence_selector": f"/manifest/{tag}[{index}]",
                }
            )
    declared = [
        {"name": attr(p, "name"), "protection_level_raw": attr(p, "protectionLevel")}
        for p in root.findall("permission")
    ]
    activities = {full_name(attr(n, "name"), package): n for n in app.findall("activity")}
    components = []
    for tag in ["activity", "activity-alias", "service", "receiver", "provider"]:
        for index, node in enumerate(app.findall(tag), 1):
            selector = f"/manifest/application/{tag}[{index}]"
            filters = [
                {
                    "actions": [attr(n, "name") for n in f.findall("action")],
                    "categories": [attr(n, "name") for n in f.findall("category")],
                    "data": [
                        {k.removeprefix(ANDROID): v for k, v in n.attrib.items()}
                        for n in f.findall("data")
                    ],
                }
                for f in node.findall("intent-filter")
            ]
            raw_exported = attr(node, "exported")
            exported = boolean(raw_exported)
            basis = "explicit" if raw_exported is not None else "intent_filter_default"
            if raw_exported is None:
                if tag == "provider":
                    exported, basis = (
                        (target <= 16 if target is not None else None),
                        "target_sdk_default",
                    )
                elif filters and (target is None or target >= 31):
                    exported, basis = None, "unresolved_missing_exported"
                    if target is not None:
                        finding(
                            "MANIFEST.EXPORTED_REQUIRED",
                            "Intent-filter component omits exported for target SDK 31+",
                            selector,
                            None,
                            "medium",
                        )
                else:
                    exported = bool(filters)
            raw_enabled = attr(node, "enabled")
            component_enabled = boolean(raw_enabled) if raw_enabled is not None else True
            enabled = (
                False
                if app_enabled is False or component_enabled is False
                else (True if app_enabled is True and component_enabled is True else None)
            )
            inherited_permission = app_permission
            alias_permission_unresolved = False
            if tag == "activity-alias":
                target_name = full_name(attr(node, "targetActivity"), package)
                target_activity = activities.get(target_name) if target_name else None
                if target_activity is None:
                    alias_permission_unresolved = attr(node, "permission") is None
                elif attr(target_activity, "permission") is not None:
                    inherited_permission = attr(target_activity, "permission")
            permission = attr(node, "permission")
            if permission is None:
                permission = inherited_permission
            read_permission = attr(node, "readPermission")
            write_permission = attr(node, "writePermission")
            read_permission = permission if read_permission is None else read_permission
            write_permission = permission if write_permission is None else write_permission
            launcher = tag in {"activity", "activity-alias"} and any(
                "android.intent.action.MAIN" in f["actions"]
                and any(
                    c in f["categories"]
                    for c in [
                        "android.intent.category.LAUNCHER",
                        "android.intent.category.LEANBACK_LAUNCHER",
                    ]
                )
                for f in filters
            )
            unguarded = (
                (not read_permission or not write_permission)
                if tag == "provider"
                else not permission
            )
            if (
                exported is True
                and enabled is True
                and unguarded
                and not launcher
                and not alias_permission_unresolved
            ):
                finding(
                    "MANIFEST.EXPORTED_REVIEW",
                    "Exported component needs access-control review",
                    selector,
                    {"type": tag, "name": attr(node, "name"), "permission": permission},
                )
            components.append(
                {
                    "type": tag,
                    "name_raw": attr(node, "name"),
                    "name": full_name(attr(node, "name"), package),
                    "enabled_from_manifest": enabled,
                    "exported_raw": raw_exported,
                    "exported_api17_plus": exported,
                    "exported_basis": basis,
                    "permission_raw": attr(node, "permission"),
                    "permission_inherited": permission,
                    "permission_resolution": "unresolved"
                    if alias_permission_unresolved
                    or (permission and permission.startswith(("@", "?")))
                    else "manifest_declaration",
                    "read_permission": read_permission if tag == "provider" else None,
                    "write_permission": write_permission if tag == "provider" else None,
                    "provider_api16_or_lower_override": tag == "provider"
                    and (minimum is None or minimum <= 16),
                    "authorities_raw": attr(node, "authorities"),
                    "target_activity": attr(node, "targetActivity"),
                    "launcher": launcher,
                    "intent_filters": filters,
                    "evidence_selector": selector,
                }
            )
    return {
        "source": {
            "member": "AndroidManifest.xml",
            "sha256": digest,
            "size_bytes": len(raw),
            "format": format_name,
            "decoder_anomalies": anomalies,
        },
        "identity": {
            "package_name": package,
            "version_name_raw": attr(root, "versionName"),
            "version_code_raw": attr(root, "versionCode"),
            "application_label_raw": attr(app, "label"),
        },
        "sdk": {
            "min_raw": min_raw,
            "target_raw": target_raw,
            "min_effective": minimum,
            "target_effective": target,
            "target_defaulted_to_min": target_raw is None,
        },
        "application": {
            "enabled": app_enabled,
            "permission": app_permission,
            "flags": app_flags,
            "network_security_config_raw": attr(app, "networkSecurityConfig"),
        },
        "permissions": permissions,
        "declared_permissions": declared,
        "components": components,
        "findings": findings,
        "limitations": [
            "Resource references are not resolved; manifest declarations are not runtime grants",
            "Exposure needs runtime, path-permission and component-state review",
            "Cleartext and backup flags alone do not establish effective policy or data exposure",
            "Plaintext XML is supported for source-style fixtures, not proof of APK installability",
        ],
    }
