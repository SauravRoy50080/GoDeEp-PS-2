"""Canonical report/review packages and offline Ed25519 detached signatures."""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import HTTPException

from godeep.schemas.report_reviews import ReviewRead
from godeep.services.report_reviews import Binder

VERSION = "1.0.0"
LIMIT = 24 * 1024 * 1024
MEMBERS = {"report.json", "reviews.json", "manifest.json"}
DOMAIN = b"GoDeEp evidence package v1\0"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode() + b"\n"


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def manifest(report_raw, reviews_raw):
    report, reviews = decode(report_raw), decode(reviews_raw)
    report_hash = digest(report_raw)
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] not in (1, 2)
        or report["report_type"] != "investigation_analysis_snapshot"
        or type(reviews["schema_version"]) is not int
        or reviews["schema_version"] != 1
        or reviews["source_report_sha256"] != report_hash
        or reviews["report_id"] != report["report_id"]
        or reviews["case_id"] != report["case"]["id"]
        or reviews["sample_id"] != report["sample"]["id"]
        or reviews["total"] != len(reviews["items"])
        or len(reviews["items"]) > 2000
    ):
        raise ValueError("package_identity_mismatch")
    if not 1 <= len(report["analyses"]) + len(report.get("runtime_captures", [])) <= 20:
        raise ValueError("source_count_invalid")
    if report.get("runtime_captures"):
        from godeep.services.runtime_review import validate

        validate(report)
    binder = Binder(report, SimpleNamespace(max_report_review_reference_bytes=67108864))
    from godeep.schemas.report_reviews import EvidenceReference

    entries = {}
    for item in reviews["items"]:
        entry = ReviewRead.model_validate(item)
        if (
            entry.id in entries
            or str(entry.report_id) != report["report_id"]
            or entry.report_sha256 != report_hash
        ):
            raise ValueError("review_identity_mismatch")
        entries[entry.id] = entry
        if len(entry.evidence_references) > 10:
            raise ValueError("reference_limit")
        for ref in entry.evidence_references:
            request = EvidenceReference.model_validate(
                {k: ref[k] for k in ("source_kind", "source_id", "pointer")}
            )
            if binder.bind(request) != ref:
                raise ValueError("review_binding_mismatch")
    superseded = set()
    for entry in entries.values():
        cursor, seen = entry, set()
        while cursor.supersedes_id:
            if cursor.id in seen:
                raise ValueError("review_cycle")
            seen.add(cursor.id)
            parent = entries[cursor.supersedes_id]
            if parent.thread_id != entry.thread_id:
                raise ValueError("review_thread_mismatch")
            cursor = parent
        if cursor.id != entry.thread_id:
            raise ValueError("review_root_mismatch")
        if entry.supersedes_id:
            if entry.supersedes_id in superseded:
                raise ValueError("review_fork")
            superseded.add(entry.supersedes_id)
    current = sorted(str(key) for key in entries if key not in superseded)
    if current != reviews["current_entry_ids"]:
        raise ValueError("review_heads_mismatch")
    return {
        "schema_version": 1,
        "package_version": VERSION,
        "report_id": report["report_id"],
        "case_id": report["case"]["id"],
        "sample_id": report["sample"]["id"],
        "input_sha256": report["sample"]["sha256"],
        "files": {
            name: {"sha256": digest(raw), "size_bytes": len(raw)}
            for name, raw in (("report.json", report_raw), ("reviews.json", reviews_raw))
        },
        "scope": "recorded_report_and_analyst_reviews_only",
        "limitations": [
            "Original APK and raw source artifacts are not included",
            "Collector claims and analysis coverage retain their source limitations",
            "A pinned key proves key possession, not legal identity or a malware verdict",
        ],
    }


def build(report_raw, reviews_raw):
    if len(report_raw) + len(reviews_raw) > LIMIT - 65536:
        raise ValueError("package_size_limit")
    meta = encode(manifest(report_raw, reviews_raw))
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_STORED) as z:
        for name, raw in sorted(
            {"report.json": report_raw, "reviews.json": reviews_raw, "manifest.json": meta}.items()
        ):
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            info.compress_type = ZIP_STORED
            z.writestr(info, raw)
    raw = buffer.getvalue()
    if len(raw) > LIMIT:
        raise ValueError("package_size_limit")
    return raw


def verify(raw):
    if len(raw) > LIMIT:
        raise ValueError("package_size_limit")
    with ZipFile(io.BytesIO(raw)) as z:
        items = z.infolist()
        if (
            len(items) != 3
            or {m.filename for m in items} != MEMBERS
            or any(
                m.compress_type != ZIP_STORED or m.flag_bits & 1 or m.file_size > LIMIT
                for m in items
            )
        ):
            raise ValueError("invalid_package_members")
        if sum(m.file_size for m in items) > LIMIT:
            raise ValueError("package_size_limit")
        report, reviews = z.read("report.json"), z.read("reviews.json")
    if raw != build(report, reviews):
        raise ValueError("noncanonical_or_changed_package")
    return manifest(report, reviews)


def signature(raw, private_key, signer):
    verify(raw)
    if not isinstance(private_key, Ed25519PrivateKey) or not 1 <= len(signer) <= 200:
        raise ValueError("invalid_signing_key_or_label")
    public = private_key.public_key().public_bytes_raw()
    unsigned = {
        "schema_version": 1,
        "algorithm": "Ed25519",
        "package_sha256": digest(raw),
        "public_key_sha256": digest(public),
        "signer_label": signer,
        "identity": "operator_label_not_independently_verified",
    }
    value = private_key.sign(DOMAIN + encode(unsigned))
    return encode({**unsigned, "signature_base64": base64.b64encode(value).decode()})


def verify_signature(raw, signature_raw, public_key):
    verify(raw)
    if not isinstance(public_key, Ed25519PublicKey) or len(signature_raw) > 4096:
        raise ValueError("invalid_signature_input")
    data = decode(signature_raw)
    if set(data) != {
        "schema_version",
        "algorithm",
        "package_sha256",
        "public_key_sha256",
        "signer_label",
        "identity",
        "signature_base64",
    }:
        raise ValueError("invalid_signature_fields")
    value = base64.b64decode(data.pop("signature_base64"), validate=True)
    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["algorithm"] != "Ed25519"
        or data["package_sha256"] != digest(raw)
        or data["public_key_sha256"] != digest(public_key.public_bytes_raw())
        or data["identity"] != "operator_label_not_independently_verified"
        or not isinstance(data["signer_label"], str)
        or not 1 <= len(data["signer_label"]) <= 200
    ):
        raise ValueError("signature_identity_mismatch")
    public_key.verify(value, DOMAIN + encode(data))
    return data


def read(path, limit):
    with path.open("rb") as f:
        raw = f.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file_size_limit")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("keygen")
    keys.add_argument("--directory", type=Path, required=True)
    sign = commands.add_parser("sign")
    for name in ("package", "private-key", "output"):
        sign.add_argument("--" + name, type=Path, required=True)
    sign.add_argument("--signer", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--package", type=Path, required=True)
    check.add_argument("--signature", type=Path)
    check.add_argument("--trusted-public-key", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            password = os.environ.get("GODEEP_SIGNING_PASSPHRASE", "").encode()
            if len(password) < 16:
                raise ValueError("signing_passphrase_required")
            key = Ed25519PrivateKey.generate()
            args.directory.mkdir(mode=0o700)
            for name, value in [
                (
                    "private.pem",
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.BestAvailableEncryption(password),
                    ),
                ),
                (
                    "public.pem",
                    key.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
                    ),
                ),
            ]:
                with (args.directory / name).open("xb") as f:
                    f.write(value)
            result = {
                "status": "keys_created",
                "public_key_sha256": digest(key.public_key().public_bytes_raw()),
            }
        else:
            raw = read(args.package, LIMIT)
            if args.command == "sign":
                password = os.environ.get("GODEEP_SIGNING_PASSPHRASE", "").encode()
                if not password:
                    raise ValueError("signing_passphrase_required")
                key = serialization.load_pem_private_key(
                    read(args.private_key, 16384), password=password
                )
                signed = signature(raw, key, args.signer)
                with args.output.open("xb") as f:
                    f.write(signed)
                result = {"status": "signed", "package_sha256": digest(raw)}
            else:
                if bool(args.signature) != bool(args.trusted_public_key):
                    raise ValueError("explicit_trusted_key_required")
                if args.signature:
                    key = serialization.load_pem_public_key(read(args.trusted_public_key, 16384))
                    result = {
                        "status": "signature_verified",
                        **verify_signature(raw, read(args.signature, 4096), key),
                    }
                else:
                    result = {"status": "package_consistent_unsigned", **verify(raw)}
        print(encode(result).decode(), end="")
        return 0
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        OSError,
        BadZipFile,
        InvalidSignature,
        UnsupportedAlgorithm,
        HTTPException,
    ):
        print('{"status":"failed","reason":"evidence_package_operation_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
