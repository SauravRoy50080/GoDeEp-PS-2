"""Research baseline arithmetic, grouped splitting and strict CSV contracts."""

import csv
import json
import math
import subprocess
import sys

import pytest

from godeep.evaluation.classifier import experiment, fit, load_csv, measure, predict, split_groups


def fixture_csv(tmp_path):
    path = tmp_path / "fixture.csv"
    rows = [[str((i >> bit) & 1) for bit in range(6)] + ["B" if i < 32 else "S"] for i in range(64)]
    with path.open("w", newline="", encoding="utf-8") as source:
        writer = csv.writer(source)
        writer.writerow([f"feature_{i}" for i in range(6)] + ["class"])
        writer.writerows(rows + rows[:10])
    return path


def test_dedup_and_split_have_no_vector_overlap(tmp_path):
    features, groups, _, count = load_csv(fixture_csv(tmp_path))
    assert len(features) == 6 and len(groups) == 64 and count == 74
    splits = split_groups(groups, "fixed")
    ids = [{r["vector_sha256"] for r in splits[name]} for name in ("train", "validation", "test")]
    assert not ids[0] & ids[1] and not ids[0] & ids[2] and not ids[1] & ids[2]
    assert sum(map(len, ids)) == 64
    assert all({r["label"] for r in rows} == {0, 1} for rows in splits.values())
    assert splits == split_groups(list(reversed(groups)), "fixed")
    assert splits != split_groups(groups, "different")


def test_naive_bayes_matches_hand_calculation():
    rows = [
        {"features": vector, "label": label}
        for vector, label in [((0, 0), 0), ((0, 1), 0), ((1, 0), 1), ((1, 1), 1)]
    ]
    model = fit(rows, 2)
    assert predict(model, (1, 0)) == pytest.approx(0.75)
    assert predict(model, (0, 0)) == pytest.approx(0.25)
    assert math.isfinite(predict(model, (1, 1)))
    with pytest.raises(ValueError):
        predict(model, (1,))


def test_metrics_match_known_confusion_and_null_denominator():
    rows = [{"label": value} for value in [1, 1, 0, 0]]
    result = measure(rows, [1, 0, 1, 0])
    assert [result[key] for key in ("tp", "fp", "tn", "fn")] == [1, 1, 1, 1]
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    assert measure(rows, [0] * 4)["precision"] is None
    with pytest.raises(ValueError):
        measure(rows, [])


def test_experiment_reproducible_train_only_model_and_unique_metrics(tmp_path):
    path = fixture_csv(tmp_path)
    first = experiment(path)
    assert first == experiment(path)
    features, groups, _, _ = load_csv(path)
    expected = fit(split_groups(groups, "godeep-malgenome-v1")["train"], len(features))
    assert first["model"]["feature_probabilities"] == expected["feature_probabilities"]
    assert first["report"]["duplicate_excess_rows"] == 10
    assert first["model"]["deployment_status"] == "research_only"
    for split in ("validation", "test"):
        stats = first["report"]["metrics"][split]["bernoulli_naive_bayes"]
        assert (
            sum(stats[key] for key in ("tp", "fp", "tn", "fn"))
            == first["report"]["splits"][split]["unique_vectors"]
        )


@pytest.mark.parametrize(
    "content",
    [
        "a,class\n2,B\n",
        "a,class\n0,X\n",
        "a,class\n0,B\n0,S\n",
        "a,a,class\n0,1,B\n",
        "a,target\n0,B\n",
        "a,class\n0,1,B\n",
        "a,class\n",
        "a,class\n0,B\n1,S\n",
    ],
)
def test_invalid_csv_and_insufficient_class_groups_rejected(tmp_path, content):
    path = tmp_path / "bad.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        experiment(path)


def test_cli_writes_json_artifacts_and_refuses_overwrite(tmp_path):
    path = fixture_csv(tmp_path)
    output = tmp_path / "run"
    command = [
        sys.executable,
        "-m",
        "godeep.evaluation.classifier",
        "--csv",
        str(path),
        "--output-dir",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert {p.name for p in output.iterdir()} == {
        "model.json",
        "report.json",
        "predictions.json",
        "assignments.json",
    }
    original = (output / "model.json").read_bytes()
    assert json.loads(original)["calibration"] == "not_calibrated"
    assert subprocess.run(command, capture_output=True, timeout=15).returncode == 2
    assert (output / "model.json").read_bytes() == original
