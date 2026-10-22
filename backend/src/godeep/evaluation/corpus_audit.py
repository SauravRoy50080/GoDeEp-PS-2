"""Read-only CSV/ZIP corpus audit; never repairs data or promotes a classifier."""

import argparse
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile

LIMIT = 16 * 1024 * 1024


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source(path, member=None):
    with path.open("rb") as f:
        raw = f.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("source_size_limit")
    provenance = {"source_name": path.name, "source_sha256": digest(raw)}
    if member:
        with ZipFile(io.BytesIO(raw)) as z:
            items = z.infolist()
            selected = [m for m in items if m.filename == member]
            if (
                len(items) > 200
                or len(selected) != 1
                or selected[0].file_size > LIMIT
                or selected[0].flag_bits & 1
                or selected[0].compress_type not in {ZIP_STORED, ZIP_DEFLATED}
            ):
                raise ValueError("zip_member_limit_or_ambiguity")
            with z.open(selected[0]) as f:
                raw = f.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("csv_size_limit")
        provenance["member"] = member
    return raw, provenance


def audit(raw, provenance):
    rows = csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
    header = next(rows, None)
    if (
        not header
        or not 2 <= len(header) <= 1001
        or header[-1] != "class"
        or len(set(header)) != len(header)
        or any(not name.strip() for name in header)
    ):
        raise ValueError("invalid_feature_schema")
    groups, labels, issues = {}, Counter(), []
    invalid, count = 0, 0
    for line, row in enumerate(rows, 2):
        count += 1
        if count > 100000:
            raise ValueError("row_limit")
        reason = (
            "column_count"
            if len(row) != len(header)
            else "invalid_label"
            if row[-1] not in {"B", "S"}
            else "nonbinary_feature"
            if any(v not in {"0", "1"} for v in row[:-1])
            else None
        )
        if len(row) == len(header) and row[-1] in {"B", "S"}:
            labels[row[-1]] += 1
        if reason:
            invalid += 1
            if len(issues) < 100:
                issues.append({"row_number": line, "reason": reason})
            continue
        vector = bytes(map(int, row[:-1]))
        key = digest(vector)
        group = groups.setdefault(key, {"vector": vector, "labels": Counter(), "rows": 0})
        group["labels"][row[-1]] += 1
        group["rows"] += 1
    conflicts = {key: item for key, item in groups.items() if len(item["labels"]) > 1}
    result = {
        "source": {**provenance, "csv_sha256": digest(raw)},
        "rows": count,
        "feature_count": len(header) - 1,
        "feature_order_sha256": digest(json.dumps(header[:-1], ensure_ascii=True).encode()),
        "label_counts": dict(labels),
        "invalid_rows": invalid,
        "row_issues": issues,
        "row_issues_limited": invalid > len(issues),
        "unique_valid_feature_vectors": len(groups),
        "duplicate_valid_rows": count - invalid - len(groups),
        "conflicting_vector_groups": len(conflicts),
        "rows_in_conflicting_groups": sum(item["rows"] for item in conflicts.values()),
        "conflicting_vector_hashes": sorted(conflicts)[:100],
        "strict_research_import_eligible": bool(count and not invalid and not conflicts),
        "production_promotion": "blocked_missing_apks_and_extractor_parity",
    }
    return result, header[:-1], groups


def compare(left, right):
    a, fa, ga = left
    b, fb, gb = right
    same = set(fa) == set(fb)
    result = {
        "feature_order_equal": fa == fb,
        "exact_feature_names_equal": same,
        "common_feature_count": len(set(fa) & set(fb)),
        "left_only_feature_names": sorted(set(fa) - set(fb)),
        "right_only_feature_names": sorted(set(fb) - set(fa)),
        "shared_aligned_feature_vectors": None,
        "right_rows_on_shared_vectors": None,
        "shared_vectors_with_label_conflicts": None,
        "independence": "unverified; feature vectors are not APK identities",
    }
    if same:
        indices = [fb.index(name) for name in fa]
        aligned = {digest(bytes(item["vector"][i] for i in indices)): item for item in gb.values()}
        shared = set(ga) & set(aligned)
        result.update(
            shared_aligned_feature_vectors=len(shared),
            right_rows_on_shared_vectors=sum(aligned[key]["rows"] for key in shared),
            shared_vectors_with_label_conflicts=sum(
                len(set(ga[key]["labels"]) | set(aligned[key]["labels"])) > 1 for key in shared
            ),
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--member")
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--compare-member")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw, provenance = source(args.dataset, args.member)
        first = audit(raw, provenance)
        result = {
            "schema_version": 1,
            "audit_version": "1.0.0",
            "dataset": first[0],
            "actions_performed": ["read_only_validation"],
            "training_performed": False,
            "limitations": [
                "No label repair, feature aliases, imputation or sample-identity inference",
                "CSV compatibility does not prove APK extractor equivalence or malware accuracy",
            ],
        }
        if args.compare:
            raw, provenance = source(args.compare, args.compare_member)
            other = audit(raw, provenance)
            result.update(comparison_dataset=other[0], comparison=compare(first, other))
        with args.output.open("xb") as f:
            f.write(json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n")
        print(json.dumps({"status": "audited", "training_performed": False}))
        return 0
    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        OSError,
        BadZipFile,
        RecursionError,
        csv.Error,
    ):
        print('{"status":"failed","reason":"corpus_audit_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
