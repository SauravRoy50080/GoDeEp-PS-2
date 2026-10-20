"""Offline benchmark integrity, leakage rejection, abstentions and CLI behaviour."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest
from test_risk_review import assertion, source

from godeep.analysis.correlation.risk import prioritize
from godeep.evaluation.priority import evaluate, strict_json


def write_corpus(tmp_path, specifications):
    entries = []
    for index, (label, positive, incomplete) in enumerate(specifications):
        digest = hashlib.sha256(str(index).encode()).hexdigest()
        data = source()
        if positive:
            data["intelligence"]["indicators"] = [assertion(["suspicious"])]
        if incomplete:
            data["coverage"]["dex"] = "partial"
        data.update(
            {
                "schema_version": 1,
                "adapter": "risk_review",
                "adapter_version": "1.0.0",
                "input_sha256": digest,
            }
        )
        data["risk_review"] = prioritize(data)
        raw = json.dumps(data).encode()
        name = f"{index}.json"
        (tmp_path / name).write_bytes(raw)
        entries.append(
            {
                "input_sha256": digest,
                "group_id": f"family-{index}",
                "split": "test",
                "label": label,
                "label_source": "synthetic fixture",
                "label_basis": "manual fixture expectation",
                "result_path": name,
                "result_sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    corpus = {
        "schema_version": 1,
        "dataset_id": "synthetic-only",
        "target": "analyst_review_priority",
        "entries": entries,
    }
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps(corpus), encoding="utf-8")
    return manifest, corpus


def save(manifest, corpus):
    manifest.write_text(json.dumps(corpus), encoding="utf-8")


def test_confusion_metrics_and_positive_abstention_bound(tmp_path):
    specs = [
        ("review_required", True, False),
        ("routine", True, False),
        ("routine", False, False),
        ("review_required", False, False),
        ("review_required", True, True),
        ("unknown", True, False),
    ]
    manifest, _ = write_corpus(tmp_path, specs)
    result = evaluate(manifest, tmp_path)
    metrics = result["metrics"]
    assert [metrics[k] for k in ("tp", "fp", "tn", "fn")] == [1, 1, 1, 1]
    assert metrics["precision"] == metrics["recall_on_assessed"] == metrics["f1_on_assessed"] == 0.5
    assert metrics["positive_abstentions"] == 1
    assert metrics["recall_lower_bound_with_positive_abstentions"] == pytest.approx(1 / 3)
    assert result["coverage_of_labelled"] == 0.8
    assert result["rows"][-1]["status"] == "unlabelled"
    assert result["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_missing_predictions_abstain_and_undefined_metrics_are_null(tmp_path):
    manifest, corpus = write_corpus(tmp_path, [("review_required", True, False)])
    corpus["entries"][0].update(result_path=None, result_sha256=None)
    save(manifest, corpus)
    result = evaluate(manifest, tmp_path)
    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall_lower_bound_with_positive_abstentions"] == 0
    assert result["coverage_of_labelled"] == 0
    assert result["rows"][0]["status"] == "abstained_missing_result"


@pytest.mark.parametrize(
    "change",
    [
        "duplicate",
        "group_overlap",
        "label",
        "target",
        "path",
        "hash",
        "score",
        "input_identity",
        "version",
        "unpaired",
        "blank_provenance",
    ],
)
def test_invalid_corpora_or_results_are_rejected(tmp_path, change):
    manifest, corpus = write_corpus(
        tmp_path, [("routine", False, False), ("review_required", True, False)]
    )
    entry = corpus["entries"][0]
    if change == "duplicate":
        corpus["entries"].append(copy.deepcopy(entry))
    elif change == "group_overlap":
        corpus["entries"][1].update(group_id=entry["group_id"], split="train")
    elif change == "label":
        entry["label"] = "malicious"
    elif change == "target":
        corpus["target"] = "malware_detection"
    elif change == "path":
        entry["result_path"] = "../outside.json"
    elif change == "hash":
        entry["result_sha256"] = "0" * 64
    elif change == "unpaired":
        entry["result_sha256"] = None
    elif change == "blank_provenance":
        entry["label_basis"] = " "
    else:
        path = tmp_path / entry["result_path"]
        data = json.loads(path.read_bytes())
        if change == "score":
            data["risk_review"]["score"] = 99
        elif change == "input_identity":
            data["input_sha256"] = "0" * 64
        else:
            data["adapter_version"] = "0.0.0"
        raw = json.dumps(data).encode()
        path.write_bytes(raw)
        entry["result_sha256"] = hashlib.sha256(raw).hexdigest()
    save(manifest, corpus)
    with pytest.raises(ValueError):
        evaluate(manifest, tmp_path)


@pytest.mark.parametrize("raw", [b'{"a": 1, "a": 2}', b'{"a":NaN}', b'{"a": Infinity}'])
def test_ambiguous_json_rejected(raw):
    with pytest.raises(ValueError):
        strict_json(raw)


def test_split_is_explicit_and_empty_split_rejected(tmp_path):
    manifest, corpus = write_corpus(
        tmp_path, [("routine", False, False), ("review_required", True, False)]
    )
    corpus["entries"][1]["split"] = "validation"
    save(manifest, corpus)
    assert evaluate(manifest, tmp_path)["selected_entries"] == 1
    assert evaluate(manifest, tmp_path, "validation")["metrics"]["tp"] == 1
    with pytest.raises(ValueError):
        evaluate(manifest, tmp_path, "train")


def test_profile_changes_are_visible(tmp_path):
    manifest, corpus = write_corpus(
        tmp_path, [("routine", False, False), ("review_required", True, False)]
    )
    path = tmp_path / "1.json"
    data = json.loads(path.read_bytes())
    data["tool_versions"] = {"fixture": "2"}
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    corpus["entries"][1]["result_sha256"] = hashlib.sha256(raw).hexdigest()
    save(manifest, corpus)
    assert evaluate(manifest, tmp_path)["mixed_observation_profiles"]


def test_size_bounds_and_cli_exclusive_output(tmp_path, monkeypatch):
    manifest, _ = write_corpus(tmp_path, [("routine", False, False)])
    output = tmp_path / "report.json"
    command = [
        sys.executable,
        "-m",
        "godeep.evaluation",
        "--manifest",
        str(manifest),
        "--results-root",
        str(tmp_path),
        "--output",
        str(output),
    ]
    run = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stderr
    original = output.read_bytes()
    assert json.loads(original)["assessed_entries"] == 1
    assert subprocess.run(command, capture_output=True, timeout=15).returncode == 2
    assert output.read_bytes() == original
    monkeypatch.setattr("godeep.evaluation.priority.MAX_RESULT_BYTES", 1)
    with pytest.raises(ValueError):
        evaluate(manifest, tmp_path)
