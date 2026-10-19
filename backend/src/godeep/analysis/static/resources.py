"""Bounded resource and declared library evidence; no recursive extraction."""

import hashlib
import re
import struct
import zlib
from pathlib import PurePosixPath
from zipfile import BadZipFile

from lxml import etree

from godeep.analysis.static.dex import URL, network_candidates
from godeep.analysis.static.manifest import preflight_axml
from godeep.integrations.analyzers.common import AdapterFailure, read_member

MAVEN = re.compile(r"META-INF/maven/([^/]+)/([^/]+)/pom\.properties\Z")
COORDINATE = re.compile(r"[A-Za-z0-9_.-]{1,200}\Z")
VERSION = re.compile(r"[A-Za-z0-9_.+()-]{1,100}\Z")


def properties(raw):
    values = {}
    for line in raw.decode("ascii").splitlines():
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)\s*[:=]\s*(.*?)\s*", line)
        if not match or "\\" in line or len(line) > 1024:
            raise ValueError("unsupported_properties_syntax")
        key, value = match.groups()
        if key in values:
            raise ValueError("ambiguous_duplicate_property")
        values[key] = value
    if not all(COORDINATE.fullmatch(values.get(key, "")) for key in ("groupId", "artifactId")):
        raise ValueError("invalid_or_missing_coordinates")
    if not VERSION.fullmatch(values.get("version", "")):
        raise ValueError("invalid_or_unresolved_version")
    return {key: values[key] for key in ("groupId", "artifactId", "version")}


def xml_policy(raw, settings):
    anomaly = False
    if raw[:2] == b"\x03\0":
        from androguard.core.axml import AXMLPrinter
        from loguru import logger

        logger.disable("androguard")
        preflight_axml(raw, settings.max_resource_nodes)
        printer = AXMLPrinter(raw)
        if not printer.is_valid():
            raise ValueError("invalid_binary_xml")
        root, format_name, anomaly = printer.get_xml_obj(), "binary_axml", printer.is_packed()
    else:
        root = etree.fromstring(
            raw,
            parser=etree.XMLParser(
                resolve_entities=False,
                load_dtd=False,
                no_network=True,
                huge_tree=False,
                recover=False,
            ),
        )
        format_name = "text_xml"
        if root.getroottree().docinfo.doctype:
            raise ValueError("resource_dtd_rejected")
    if root is None:
        raise ValueError("invalid_xml")
    declarations, urls = [], []
    nodes = list(root.iter())
    if len(nodes) > settings.max_resource_nodes:
        raise ValueError("resource_node_limit")
    for node in nodes:
        if not isinstance(node.tag, str):
            continue
        selector = node.getroottree().getpath(node)
        for label, value in [
            ("text()", node.text or ""),
            *[("@" + k, v) for k, v in node.attrib.items()],
        ]:
            for match in URL.finditer(value):
                for kind, candidate in network_candidates(match.group(0)):
                    if len(urls) >= settings.max_resource_findings:
                        raise ValueError("resource_url_limit")
                    urls.append(
                        {
                            "kind": kind,
                            "value": candidate,
                            "selector": selector + "/" + label,
                            "source_span": "decoded_xml_value",
                        }
                    )
        if root.tag != "network-security-config":
            continue
        for key, value in node.attrib.items():
            if key in (
                "cleartextTrafficPermitted",
                "src",
                "overridePins",
                "includeSubdomains",
                "expiration",
            ):
                if len(value) > 2048:
                    raise ValueError("resource_value_limit")
                declarations.append({"selector": selector + "/@" + key, "value": value})
        if node.tag == "domain" and node.text:
            if len(node.text) > 2048:
                raise ValueError("resource_value_limit")
            declarations.append({"selector": selector + "/text()", "value": node.text.strip()})
        if len(declarations) > settings.max_resource_findings:
            raise ValueError("resource_declaration_limit")
    return {
        "format": format_name,
        "root": root.tag,
        "decoder_anomalies": anomaly,
        "resource_reference_binding": "not_resolved",
        "declarations": declarations,
        "url_candidates": urls,
    }


def inspect_resources(archive, settings):
    files, libraries, candidates, skipped = [], [], [], []
    total, skipped_count, candidate_count = 0, 0, 0
    partial = False

    def skip(member, reason):
        nonlocal partial, skipped_count
        partial = True
        skipped_count += 1
        if len(skipped) < 100:
            skipped.append({"member": member.filename, "reason": reason})

    for member in archive.infolist():
        name = member.filename
        maven = MAVEN.fullmatch(name)
        marker = name.startswith("META-INF/") and name.endswith(".version")
        native = name.startswith("lib/") and name.endswith(".so")
        if member.is_dir() or not (
            name.startswith(("assets/", "res/raw/", "res/xml/", "res/xml-"))
            or maven
            or marker
            or native
        ):
            continue
        if len(files) >= settings.max_resource_files:
            skip(member, "resource_file_count_limit")
            continue
        if member.file_size > settings.max_resource_bytes:
            skip(member, "resource_member_size_limit")
            continue
        if total + member.file_size > settings.max_resource_total_bytes:
            skip(member, "resource_total_size_limit")
            continue
        total += member.file_size
        try:
            raw = read_member(archive, member, settings.max_resource_bytes)
        except (AdapterFailure, BadZipFile, NotImplementedError, RuntimeError, zlib.error):
            skip(member, "resource_read_failed")
            continue
        source = {"member": name, "sha256": hashlib.sha256(raw).hexdigest()}
        item = {**source, "size_bytes": len(raw), "coverage": "hashed_and_classified"}
        files.append(item)
        if raw.startswith(b"dex\n"):
            item["format"] = "embedded_dex_candidate"
        elif raw.startswith(b"PK\x03\x04"):
            item["format"] = "embedded_zip_candidate"
        elif raw.startswith(b"\x7fELF"):
            item["format"] = "elf_candidate"
            if len(raw) >= 20 and raw[4] in (1, 2) and raw[5] in (1, 2):
                item["elf_header"] = {
                    "bits": 32 if raw[4] == 1 else 64,
                    "endianness": "little" if raw[5] == 1 else "big",
                    "machine_id": struct.unpack_from("<H" if raw[5] == 1 else ">H", raw, 18)[0],
                    "abi_directory": PurePosixPath(name).parts[1]
                    if native and len(PurePosixPath(name).parts) == 3
                    else None,
                }
            else:
                item["coverage"] = "invalid_elf_header"
                partial = True
        else:
            item["format"] = "unclassified"
        try:
            if maven:
                declared = properties(raw)
                match = declared["groupId"] == maven[1] and declared["artifactId"] == maven[2]
                libraries.append(
                    {
                        **source,
                        "kind": "maven_properties",
                        **declared,
                        "path_identity_matches": match,
                        "evidence_state": "declared_metadata",
                        "identity_verified": False,
                        "vulnerability_status": "not_queried",
                    }
                )
                if not match:
                    item["coverage"] = "metadata_path_conflict"
                    partial = True
            elif marker:
                value = raw.decode("ascii").strip()
                if not VERSION.fullmatch(value):
                    raise ValueError("invalid_version_marker")
                libraries.append(
                    {
                        **source,
                        "kind": "version_marker",
                        "marker": name,
                        "version_declared": value,
                        "identity_verified": False,
                        "evidence_state": "filename_marker_candidate",
                        "vulnerability_status": "not_queried",
                    }
                )
            elif name.endswith(".xml"):
                item["xml"] = xml_policy(raw, settings)
                if item["xml"]["decoder_anomalies"]:
                    partial = True
                for candidate in item["xml"].pop("url_candidates"):
                    if candidate_count >= settings.max_resource_findings:
                        partial = True
                        item["candidate_output_limited"] = True
                        break
                    candidate_count += 1
                    candidates.append(
                        {
                            **source,
                            **candidate,
                            "evidence_state": "resource_string_candidate",
                            "reputation": "not_checked",
                        }
                    )
            if item["format"] == "unclassified" and "xml" not in item:
                try:
                    text = raw.decode("utf-8")
                except UnicodeError:
                    continue
                for match in URL.finditer(text):
                    if candidate_count >= settings.max_resource_findings:
                        partial = True
                        item["candidate_output_limited"] = True
                        break
                    for kind, value in network_candidates(match.group(0)):
                        if candidate_count >= settings.max_resource_findings:
                            partial = True
                            item["candidate_output_limited"] = True
                            break
                        candidate_count += 1
                        candidates.append(
                            {
                                **source,
                                "kind": kind,
                                "value": value,
                                "byte_offset": len(text[: match.start()].encode("utf-8")),
                                "source_span": "url_literal",
                                "evidence_state": "resource_string_candidate",
                                "reputation": "not_checked",
                            }
                        )
        except (ValueError, etree.XMLSyntaxError, AdapterFailure):
            item["coverage"] = "parse_failed"
            # Stable categories only; do not echo parser exception text or resource content.
            item["error_code"] = "resource_metadata_or_xml_invalid_or_unsupported"
            partial = True
    return {
        "files": files,
        "library_candidates": libraries,
        "network_candidates": candidates,
        "skipped": skipped,
        "skipped_count": skipped_count,
        "skipped_records_truncated": skipped_count > len(skipped),
        "declared_bytes_attempted": total,
        "coverage": "partial"
        if partial
        else "selected_members_inspected"
        if files
        else "no_selected_members",
        "limitations": [
            "Selected resources only; resources.arsc and resource binding are unresolved",
            "Library declarations and version markers do not verify packaged code or vulnerability",
            "Network policies may be unused or overridden; no effective runtime policy is inferred",
            "Embedded ZIP/DEX and ELF headers are classified, not executed or recursively analyzed",
            "Only UTF-8 text URL literals are scanned; encrypted and encoded content may be missed",
        ],
    }
