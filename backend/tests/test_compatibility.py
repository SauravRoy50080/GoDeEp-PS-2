"""Tri-state extraction prevents silent zero filling and preserves manifest evidence."""

import hashlib
import json
import subprocess
import sys

import pytest
from android_fixtures import MANIFEST, binary_manifest

from godeep.analysis.static.manifest import parse_manifest
from godeep.core.config import Settings
from godeep.evaluation.compatibility import align, audit, categories

FEATURES = ["READ_SMS", "CAMERA", "Runtime.exec", ".system.bin"]
MAPPING = {
    "READ_SMS": "Manifest Permission",
    "CAMERA": "Manifest Permission",
    "Runtime.exec": "API call signature",
    "class": "B=Benign; S=Malware",
}


def result(xml=MANIFEST):
    return {
        "schema_version": 1,
        "adapter": "static_review",
        "adapter_version": "1.0.1",
        "input_sha256": "a" * 64,
        "manifest": parse_manifest(binary_manifest(xml), Settings(_env_file=None)),
        "coverage": {"manifest": {"status": "parsed"}},
    }


def inputs(tmp_path):
    source = tmp_path / "source.csv"
    source.write_text(",".join(FEATURES + ["class"]) + "\n1,0,1,0,S\n0,1,0,1,B\n", encoding="utf-8")
    mapping = tmp_path / "mapping.csv"
    mapping.write_text(
        "\n".join(f"{key},{value}" for key, value in MAPPING.items()), encoding="utf-8"
    )
    output = tmp_path / "result.json"
    raw = json.dumps(result()).encode()
    output.write_bytes(raw)
    return source, mapping, output, hashlib.sha256(raw).hexdigest()


def test_supported_declarations_unknowns_and_qualifiers_preserved():
    report = align(FEATURES, MAPPING, result())
    assert report["state_counts"] == {"declared": 1, "not_declared": 1, "unknown": 2}
    rows = report["observations"]
    assert rows[0]["value"] == 1 and rows[0]["evidence"][0]["max_sdk_version_raw"] == "32"
    assert rows[1]["value"] == 0 and rows[1]["source_manifest_sha256"]
    assert rows[2]["value"] is None and rows[3]["value"] is None
    assert report["unmapped_features"] == [".system.bin"]
    assert report["prediction_allowed"] is False and report["model_input"] is None


@pytest.mark.parametrize("status", ["failed", "parsed_with_anomalies", "not_analyzed"])
def test_unavailable_or_anomalous_manifest_never_implies_zero(status):
    data = result()
    data["coverage"]["manifest"]["status"] = status
    report = align(FEATURES, MAPPING, data)
    assert report["state_counts"]["unknown"] == 4
    assert all(row["value"] is None for row in report["observations"])


def test_namespaces_and_permission_elements_remain_distinct():
    xml = MANIFEST.replace("android.permission.READ_SMS", "com.example.READ_SMS")
    assert align(FEATURES, MAPPING, result(xml))["observations"][0]["value"] == 0
    xml = MANIFEST.replace("uses-permission ", "uses-permission-sdk-23 ")
    evidence = align(FEATURES, MAPPING, result(xml))["observations"][0]["evidence"][0]
    assert evidence["element"] == "uses-permission-sdk-23"


@pytest.mark.parametrize("field", ["permissions", "source"])
def test_inconsistent_parsed_manifest_rejected(field):
    data = result()
    data["manifest"].pop(field)
    with pytest.raises(ValueError):
        align(FEATURES, MAPPING, data)


def test_hash_identity_and_feature_order_provenance(tmp_path):
    args = inputs(tmp_path)
    report = audit(*args)
    assert report["result_sha256"] == args[3]
    assert report["dataset_sha256"] and report["category_mapping_sha256"]
    assert [row["feature"] for row in report["observations"]] == FEATURES
    assert (
        align(list(reversed(FEATURES)), MAPPING, result())["feature_order_sha256"]
        != report["feature_order_sha256"]
    )
    with pytest.raises(ValueError):
        audit(*args[:3], "0" * 64)
    data = result()
    data["adapter_version"] = "future-version"
    raw = json.dumps(data).encode()
    args[2].write_bytes(raw)
    with pytest.raises(ValueError):
        audit(*args[:3], hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize(
    "content",
    [
        "feature,category\nREAD_SMS,Manifest Permission",
        "class,B=Benign; S=Malware\nREAD_SMS,Manifest Permission\nREAD_SMS,API call signature",
        "class,wrong",
        "class,B=Benign; S=Malware\nblank,",
    ],
)
def test_invalid_headerless_mapping_rejected(tmp_path, content):
    path = tmp_path / "mapping.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        categories(path)


def test_even_all_observed_features_do_not_establish_semantic_compatibility():
    report = align(["READ_SMS"], MAPPING, result())
    assert report["state_counts"]["unknown"] == 0
    assert not report["prediction_allowed"]
    assert report["compatibility_status"] == "blocked_unverified_extraction_semantics"


def test_cli_preserves_existing_output(tmp_path):
    source, mapping, analysis, digest = inputs(tmp_path)
    output = tmp_path / "audit.json"
    command = [
        sys.executable,
        "-m",
        "godeep.evaluation.compatibility",
        "--csv",
        str(source),
        "--categories",
        str(mapping),
        "--result",
        str(analysis),
        "--result-sha256",
        digest,
        "--output",
        str(output),
    ]
    process = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert process.returncode == 0, process.stderr
    raw = output.read_bytes()
    assert json.loads(raw)["prediction_allowed"] is False
    assert subprocess.run(command, capture_output=True, timeout=15).returncode == 2
    assert output.read_bytes() == raw
