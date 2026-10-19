"""Bounded certificate extraction; never claims APK signature verification."""

import hashlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7

from godeep.integrations.analyzers.common import read_member


def signing_block_state(path, central_offset, limit):
    if central_offset < 24:
        return "absent"
    with path.open("rb") as source:
        source.seek(central_offset - 24)
        footer = source.read(24)
        size, magic = struct.unpack("<Q16s", footer)
        if magic != b"APK Sig Block 42":
            return "absent"
        start = central_offset - size - 8
        if size < 24 or size > limit or start < 0:
            return "invalid_or_over_limit"
        source.seek(start)
        return (
            "present_bounded"
            if source.read(8) == struct.pack("<Q", size)
            else "invalid_or_over_limit"
        )


def certificate_info(cert, source):
    key = cert.public_key()
    subject, issuer = cert.subject.rfc4514_string(), cert.issuer.rfc4514_string()
    return {
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "serial_number_hex": format(cert.serial_number, "x"),
        "subject": subject[:4096],
        "issuer": issuer[:4096],
        "names_truncated": len(subject) > 4096 or len(issuer) > 4096,
        "subject_equals_issuer": cert.subject == cert.issuer,
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "public_key_type": type(key).__name__,
        "public_key_bits": getattr(key, "key_size", None),
        "signature_algorithm_oid": cert.signature_algorithm_oid.dotted_string,
        "sources": [source],
        "verification": "not_performed",
    }


def inspect_signing(path, archive, settings):
    certificates, issues, candidates = {}, [], []
    schemes = {"v1_candidate_blocks": 0, "v2_block": False, "v3_block": False, "v31_block": False}

    def add(cert, source):
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        if fingerprint in certificates:
            certificates[fingerprint]["sources"].append(source)
        elif len(certificates) < settings.max_certificates:
            certificates[fingerprint] = certificate_info(cert, source)
        else:
            issues.append("certificate_count_limit")

    total = 0
    for index, member in enumerate(archive.infolist()):
        if not (
            member.filename.upper().startswith("META-INF/")
            and member.filename.upper().endswith((".RSA", ".DSA", ".EC"))
        ):
            continue
        schemes["v1_candidate_blocks"] += 1
        total += member.file_size
        if total > settings.max_signature_bytes or len(candidates) >= settings.max_certificates:
            issues.append("signature_member_limit")
            continue
        source = {
            "member": member.filename[:256],
            "member_index": index,
            "member_name_truncated": len(member.filename) > 256,
        }
        candidates.append(source)
        try:
            raw = read_member(archive, member, settings.max_certificate_member_bytes)
            source["sha256"] = hashlib.sha256(raw).hexdigest()
            for cert in pkcs7.load_der_pkcs7_certificates(raw):
                add(cert, source)
        except Exception:
            issues.append("v1_certificate_parse_error")
    state = signing_block_state(path, archive.start_dir, settings.max_signature_bytes)
    if state == "present_bounded":
        try:
            from androguard.core.apk import APK
            from loguru import logger

            logger.disable("androguard")
            apk = APK(str(path), skip_analysis=True)
            for label, check, extract in [
                ("v2_block", apk.is_signed_v2, apk.get_certificates_der_v2),
                ("v3_block", apk.is_signed_v3, apk.get_certificates_der_v3),
                ("v31_block", apk.is_signed_v31, apk.get_certificates_der_v31),
            ]:
                try:
                    schemes[label] = bool(check())
                    if schemes[label]:
                        ders = extract()
                        if not ders:
                            issues.append(label + "_no_certificates")
                        if len(ders) > settings.max_certificates:
                            issues.append("certificate_count_limit")
                        for der in ders[: settings.max_certificates]:
                            if len(der) > settings.max_certificate_member_bytes:
                                issues.append("certificate_size_limit")
                                continue
                            add(x509.load_der_x509_certificate(der), {"block": label})
                except Exception:
                    issues.append(label + "_certificate_parse_error")
        except Exception:
            issues.append("signing_block_parse_error")
    elif state == "invalid_or_over_limit":
        issues.append("signing_block_invalid_or_over_limit")
    return {
        "cryptographic_verification": "not_performed",
        "apk_signing_block": state,
        "candidate_schemes": schemes,
        "v1_candidates": candidates,
        "certificates": list(certificates.values()),
        "issues": sorted(set(issues)),
        "coverage": "partial" if issues else "metadata_extraction_only",
        "limitations": [
            "Certificate presence and parsed scheme blocks do not prove a valid APK signature",
            "v1 certificates are embedded PKCS7 metadata, not verified JAR signers",
            "v2/v3/v3.1 signatures, digests, lineage and Android compatibility are not verified",
            "v4 sidecars are not analyzed; no installability or certificate reputation verdict",
        ],
    }
