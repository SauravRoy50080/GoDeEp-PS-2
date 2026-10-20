"""Validation-only selection boundaries, arithmetic and exclusion of test scoring."""

import copy
import json
import subprocess
import sys

import pytest
from test_classifier import fixture_csv

from godeep.evaluation.classifier import load_csv, split_groups
from godeep.evaluation.selection import choose, compare, fit_stump, stump_score


def candidate(recall=0.75, fpr=0.05, f1=0.8, name="fixture", threshold=0.5):
    return {
        "algorithm": name,
        "threshold": threshold,
        "metrics": {"recall": recall, "false_positive_rate": fpr, "f1": f1},
    }


def test_stump_training_matches_hand_counts_and_tie_break():
    rows = [{"features": (value, value), "label": value} for value in [0, 0, 1, 1]]
    model = fit_stump(rows, 2)
    assert model["feature_index"] == 0
    assert model["training_impurity"] == 0
    assert model["leaf_class_counts"] == [[2, 0], [0, 2]]
    assert stump_score(model, (0, 0)) == 0.25
    assert stump_score(model, (1, 1)) == 0.75


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [{"features": (0,), "label": 0}],
        [{"features": (0,), "label": label} for label in [0, 1]],
    ],
)
def test_stump_rejects_no_split_or_insufficient_classes(rows):
    with pytest.raises(ValueError):
        fit_stump(rows, 1)


def test_objective_boundaries_and_no_silent_fallback():
    assert choose([candidate(fpr=0.050001)]) is None
    assert choose([candidate(recall=0.49999)]) is None
    assert choose([candidate(recall=None)]) is None
    boundary = candidate(recall=0.5)
    assert choose([boundary]) == boundary
    assert choose([]) is None


def test_selection_rank_and_order_independence():
    a = candidate(recall=0.8, f1=0.8, name="a")
    b = candidate(recall=0.9, f1=0.6, name="b")
    c = candidate(recall=0.9, f1=0.7, name="c")
    d = candidate(recall=0.9, f1=0.7, fpr=0.04, name="d")
    assert choose([a, b, c, d]) == choose([d, c, b, a]) == d


def test_comparison_reproducible_and_research_only(tmp_path):
    path = fixture_csv(tmp_path)
    result = compare(path)
    assert result == compare(path)
    report = result["report"]
    assert report["test_evaluation"] == "not_performed"
    assert len(report["candidates"]) == 18
    assert report["selected"]["metrics"]["false_positive_rate"] <= 0.05
    assert result["candidate"]["deployment_status"] == "validation_candidate_only"
    assert result["candidate"]["calibration"] == "not_calibrated"


def test_test_features_and_labels_never_read_for_scoring(tmp_path, monkeypatch):
    path = fixture_csv(tmp_path)
    _, groups, _, _ = load_csv(path)
    splits = split_groups(groups, "godeep-malgenome-v1")

    class Guard(dict):
        def __getitem__(self, key):
            if key in {"features", "label"}:
                raise AssertionError("Test observations used during selection")
            return super().__getitem__(key)

    splits["test"] = [Guard(row) for row in splits["test"]]
    monkeypatch.setattr("godeep.evaluation.selection.split_groups", lambda groups, seed: splits)
    assert compare(path)["report"]["test_evaluation"] == "not_performed"


def test_validation_can_select_threshold_without_changing_training_parameters(
    tmp_path, monkeypatch
):
    path = fixture_csv(tmp_path)
    first = compare(path)
    _, groups, _, _ = load_csv(path)
    splits = split_groups(groups, "godeep-malgenome-v1")
    original = copy.deepcopy(splits["train"])
    for row in splits["validation"]:
        row["label"] = 1 - row["label"]
    monkeypatch.setattr("godeep.evaluation.selection.split_groups", lambda groups, seed: splits)
    second = compare(path)
    assert splits["train"] == original
    assert first["report"]["candidates"] != second["report"]["candidates"]


def test_cli_artifacts_and_overwrite_refusal(tmp_path):
    path = fixture_csv(tmp_path)
    output = tmp_path / "comparison"
    command = [
        sys.executable,
        "-m",
        "godeep.evaluation.selection",
        "--csv",
        str(path),
        "--output-dir",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert {p.name for p in output.iterdir()} == {
        "report.json",
        "candidate.json",
        "assignments.json",
    }
    assert json.loads((output / "report.json").read_bytes())["test_evaluation"] == "not_performed"
    assert subprocess.run(command, capture_output=True, timeout=15).returncode == 2
