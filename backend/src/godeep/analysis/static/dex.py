"""Bounded DEX identifier-table triage; no instruction execution or call claims."""

import hashlib
import ipaddress
import re
import struct
from urllib.parse import urlsplit

from godeep.integrations.analyzers.common import AdapterFailure

RULES = {
    ("Ldalvik/system/DexClassLoader;", "<init>"): "dynamic_loading",
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"): "dynamic_loading",
    ("Ljava/lang/reflect/Method;", "invoke"): "reflection",
    ("Ljava/lang/Runtime;", "exec"): "process_execution",
    ("Ljava/lang/System;", "loadLibrary"): "native_loading",
    ("Landroid/os/Debug;", "isDebuggerConnected"): "debugger_check",
    ("Landroid/telephony/SmsManager;", "sendTextMessage"): "sms_send",
    ("Landroid/location/LocationManager;", "getLastKnownLocation"): "location_access",
    ("Landroid/media/MediaRecorder;", "start"): "media_recording",
}
URL = re.compile(r"https?://[^\s<>\"'\x00-\x1f]+", re.IGNORECASE)
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.I)


def network_candidates(value):
    """Return syntactic candidates only; never resolve, connect or enrich."""
    found = set()
    for match in URL.finditer(value):
        raw = match.group(0)
        try:
            host = urlsplit(raw).hostname
            if host:
                found.add(("url", raw))
                try:
                    found.add(("ip", str(ipaddress.ip_address(host))))
                except ValueError:
                    if DOMAIN.fullmatch(host):
                        found.add(("domain", host.lower()))
        except ValueError:
            continue
    # Standalone values avoid matching Java package names inside descriptors.
    try:
        found.add(("ip", str(ipaddress.ip_address(value))))
    except ValueError:
        pass
    return sorted(found)


def parse_dex(raw, settings, *, include_tables=False):
    def fail():
        raise AdapterFailure("dex_parse_failed")

    def uint(offset):
        if offset < 0 or offset + 4 > len(raw):
            fail()
        return struct.unpack_from("<I", raw, offset)[0]

    if len(raw) < 112 or raw[:4] != b"dex\n" or raw[7] != 0:
        fail()
    version = raw[4:7]
    if version not in (b"035", b"037", b"038", b"039", b"040"):
        raise AdapterFailure("dex_format_unsupported")
    if uint(32) != len(raw) or uint(36) != 112 or uint(40) != 0x12345678:
        fail()
    if len(raw) > settings.max_dex_bytes:
        raise AdapterFailure("dex_limits_exceeded")

    def table(header, width):
        count, offset = uint(header), uint(header + 4)
        if count > settings.max_dex_identifiers:
            raise AdapterFailure("dex_limits_exceeded")
        if count and (offset < 112 or offset % 4 or offset + count * width > len(raw)):
            fail()
        if not count and offset:
            fail()
        return count, offset

    sc, so = table(56, 4)
    tc, to = table(64, 4)
    pc, _ = table(72, 12)
    mc, mo = table(88, 8)
    strings, locations, indicators = [], [], []
    truncated = False
    for i in range(sc):
        pos = uint(so + i * 4)
        if pos < 112 or pos >= len(raw):
            fail()
        original = pos
        units = 0
        for shift in range(0, 35, 7):
            if pos >= len(raw):
                fail()
            byte = raw[pos]
            pos += 1
            if shift == 28 and byte > 15:
                fail()
            units |= (byte & 127) << shift
            if not byte & 128:
                break
        else:
            fail()
        end = raw.find(b"\0", pos, min(len(raw), pos + settings.max_dex_string_bytes + 1))
        if end < 0:
            raise AdapterFailure("dex_string_invalid_or_over_limit")
        encoded = raw[pos:end]
        try:
            # DEX modified UTF-8 encodes NUL as C0 80 and supplementary characters
            # as UTF-16 surrogate pairs, never four-byte UTF-8 sequences.
            if any(byte >= 240 for byte in encoded):
                fail()
            value = encoded.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
            if len(value.encode("utf-16-le", "surrogatepass")) // 2 != units:
                fail()
            value = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeError:
            fail()
        strings.append(value)
        locations.append(original)
        for kind, candidate in network_candidates(value):
            if len(indicators) < settings.max_dex_findings:
                indicators.append(
                    {
                        "kind": kind,
                        "value": candidate,
                        "string_index": i,
                        "byte_offset": original,
                        "evidence_state": "string_literal_candidate",
                    }
                )
            else:
                truncated = True
    types = []
    for i in range(tc):
        index = uint(to + 4 * i)
        if index >= sc:
            fail()
        types.append(strings[index])
    references, method_ids = [], []
    for i in range(mc):
        offset = mo + i * 8
        cls, proto, name = struct.unpack_from("<HHI", raw, offset)
        if cls >= tc or proto >= pc or name >= sc:
            fail()
        if include_tables:
            method_ids.append((cls, proto, name))
        category = RULES.get((types[cls], strings[name]))
        if category:
            if len(references) < settings.max_dex_findings:
                references.append(
                    {
                        "rule_id": "DEX." + category.upper(),
                        "category": category,
                        "class_descriptor": types[cls],
                        "method_name": strings[name],
                        "method_index": i,
                        "byte_offset": offset,
                        "evidence_state": "method_identifier_reference",
                        "requires_review": True,
                    }
                )
            else:
                truncated = True
    result = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": version.decode(),
        "counts": {"strings": sc, "types": tc, "methods": mc},
        "api_references": references,
        "network_candidates": indicators,
        "coverage": "partial_output_limit" if truncated else "identifier_tables_parsed",
        "full_dex_validation": "not_performed",
    }

    if include_tables:
        result["_tables"] = (strings, types, method_ids)
    return result
