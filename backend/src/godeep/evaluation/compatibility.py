"""Offline tri-state feature alignment; never converts unsupported extraction to zero."""

import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter
from pathlib import Path

from godeep.evaluation.classifier import load_csv
from godeep.evaluation.priority import bounded, strict_json

VERSION = "1.0.0"
DIGEST = re.compile(r"[a-f0-9]{64}")
PERMISSION = re.compile(r"[A-Z][A-Z0-9_]*")


def categories(path):
    raw = bounded(Path(path), 1024 * 1024)
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
    if not rows or len(rows) > 2000:
        raise ValueError("Category mapping dimensions invalid")
    mapping = {}
    for row in rows:
        if len(row) != 2 or not all(value.strip() for value in row) or row[0] in mapping:
            raise ValueError("Expected unique headerless feature/category pairs")
        mapping[row[0]] = row[1]
    if mapping.get("class") != "B=Benign; S=Malware":
        raise ValueError("Category mapping must explicitly establish B/S label semantics")
    return mapping, hashlib.sha256(raw).hexdigest()


def align(features, mapping, data):
    status = data.get("coverage", {}).get("manifest", {}).get("status")
    manifest = data.get("manifest")
    permissions = []
    if status == "parsed":
        if not isinstance(manifest, dict) or not isinstance(manifest.get("permissions"), list):
            raise ValueError("Parsed manifest lacks permission records")
        if not DIGEST.fullmatch(manifest.get("source", {}).get("sha256", "")):
            raise ValueError("Missing manifest source digest")
        permissions = manifest["permissions"]
        for item in permissions:
            if (
                not isinstance(item.get("name"), str)
                or not isinstance(item.get("evidence_selector"), str)
                or item.get("element")
                not in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}
            ):
                raise ValueError("Malformed permission observation")
    observations = []
    for index, feature in enumerate(features):
        category = mapping.get(feature)
        supported = category == "Manifest Permission" and PERMISSION.fullmatch(feature) is not None
        record = {
            "index": index,
            "feature": feature,
            "category": category,
            "value": None,
            "state": "unknown",
            "evidence": [],
        }
        if not supported:
            record["reason"] = (
                "unmapped_feature"
                if category is None
                else "extractor_not_implemented_for_this_feature"
            )
        elif status != "parsed":
            record["reason"] = "manifest_unavailable_or_anomalous"
        else:
            name = "android.permission." + feature
            matches = [item for item in permissions if item["name"] == name]
            record.update(
                {
                    "value": int(bool(matches)),
                    "state": "declared" if matches else "not_declared",
                    "reason": "candidate_manifest_declaration_mapping",
                    "permission_name": name,
                    "evidence": [
                        {
                            "member": "AndroidManifest.xml",
                            "sha256": manifest["source"]["sha256"],
                            "selector": item["evidence_selector"],
                            "element": item["element"],
                            "max_sdk_version_raw": item.get("max_sdk_version_raw"),
                            "uses_permission_flags_raw": item.get("uses_permission_flags_raw"),
                        }
                        for item in matches
                    ],
                    "source_manifest_sha256": manifest["source"]["sha256"],
                }
            )
        observations.append(record)
    counts = dict(Counter(item["state"] for item in observations))
    return {
        "alignment_version": VERSION,
        "feature_order_sha256": hashlib.sha256(
            json.dumps(features, separators=(",", ":")).encode()
        ).hexdigest(),
        "feature_count": len(features),
        "state_counts": {
            name: counts.get(name, 0) for name in ("declared", "not_declared", "unknown")
        },
        "observations": observations,
        "unmapped_features": [name for name in features if name not in mapping],
        "unused_mapping_features": sorted(set(mapping) - set(features) - {"class"}),
        "compatibility_status": "blocked_unverified_extraction_semantics",
        "prediction_allowed": False,
        "model_input": None,
        "limitations": [
            "Candidate permission alignment does not verify original dataset extraction semantics",
            "Not declared describes this manifest only, not runtime permission state",
            "SDK qualifiers remain evidence; permission effectiveness and grants are unresolved",
            "Unsupported features remain null and must never be zero-filled",
            "API, intent and command features need independently verified extraction mappings",
            "No prediction, training, original APK rehash or network request is performed",
        ],
    }


def audit(csv_path, category_path, result_path, expected_result_sha256):
    if not DIGEST.fullmatch(expected_result_sha256):
        raise ValueError("Expected lowercase result SHA-256")
    features, _, source_digest, _ = load_csv(csv_path)
    mapping, category_digest = categories(category_path)
    raw = bounded(Path(result_path), 10 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_result_sha256:
        raise ValueError("Result digest mismatch")
    data = strict_json(raw)
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or (data.get("adapter"), data.get("adapter_version"))
        not in {
            ("static_review", "1.0.1"),
            ("threat_review", "1.0.0"),
            ("risk_review", "1.0.0"),
            ("evasion_review", "1.0.0"),
        }
        or not DIGEST.fullmatch(data.get("input_sha256", ""))
    ):
        raise ValueError("Unsupported analysis identity/version")
    report = align(features, mapping, data)
    report.update(
        {
            "schema_version": 1,
            "dataset_sha256": source_digest,
            "category_mapping_sha256": category_digest,
            "result_sha256": expected_result_sha256,
            "input_sha256": data["input_sha256"],
            "adapter": data["adapter"],
            "adapter_version": data["adapter_version"],
            "manifest_coverage": data.get("coverage", {}).get("manifest", {}),
        }
    )
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Audit tri-state feature compatibility; no inference"
    )
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--categories", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--result-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = audit(args.csv, args.categories, args.result, args.result_sha256)
        raw = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
        with args.output.open("x", encoding="utf-8") as destination:
            destination.write(raw + "\n")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, csv.Error):
        parser.exit(
            2, "Compatibility audit failed: check schemas, hashes, mappings and output path.\n"
        )
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "feature_count",
                    "state_counts",
                    "prediction_allowed",
                    "compatibility_status",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
