"""Research-only binary feature baseline; no APK parsing or production inference."""

import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path

VERSION = "1.0.0"
MAX_BYTES = 16 * 1024 * 1024


def load_csv(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("CSV size limit exceeded")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
    if not rows or not 2 <= len(rows[0]) <= 1001 or len(rows) > 100001:
        raise ValueError("CSV dimensions invalid")
    header = rows.pop(0)
    if (
        header[-1] != "class"
        or len(set(header)) != len(header)
        or any(not name.strip() for name in header)
    ):
        raise ValueError("Expected unique feature names followed by class")
    groups = {}
    for row in rows:
        if (
            len(row) != len(header)
            or row[-1] not in {"B", "S"}
            or any(value not in {"0", "1"} for value in row[:-1])
        ):
            raise ValueError("Expected binary features and explicit B/S labels")
        vector = tuple(int(value) for value in row[:-1])
        key = hashlib.sha256(bytes(vector)).hexdigest()
        label = int(row[-1] == "S")
        if key in groups:
            if groups[key]["label"] != label:
                raise ValueError("Identical vector has conflicting labels")
            groups[key]["source_rows"] += 1
        else:
            groups[key] = {
                "vector_sha256": key,
                "features": vector,
                "label": label,
                "source_rows": 1,
            }
    if not groups:
        raise ValueError("Empty dataset")
    return (
        header[:-1],
        sorted(groups.values(), key=lambda item: item["vector_sha256"]),
        hashlib.sha256(raw).hexdigest(),
        len(rows),
    )


def split_groups(groups, seed):
    splits = {"train": [], "validation": [], "test": []}
    for label in (0, 1):
        selected = [group for group in groups if group["label"] == label]
        if len(selected) < 10:
            raise ValueError("At least ten unique vectors per class required")
        selected.sort(
            key=lambda item: hashlib.sha256(
                (seed + ":" + item["vector_sha256"]).encode()
            ).hexdigest()
        )
        held = max(1, len(selected) // 10)
        splits["test"] += selected[:held]
        splits["validation"] += selected[held : 2 * held]
        splits["train"] += selected[2 * held :]
    for items in splits.values():
        items.sort(key=lambda item: item["vector_sha256"])
    return splits


def fit(rows, width):
    counts = [sum(row["label"] == label for row in rows) for label in (0, 1)]
    if not all(counts):
        raise ValueError("Training requires both classes")
    probabilities = []
    for label in (0, 1):
        positives = [0] * width
        for row in rows:
            if row["label"] == label:
                for index, value in enumerate(row["features"]):
                    positives[index] += value
        probabilities.append([(value + 1) / (counts[label] + 2) for value in positives])
    return {
        "algorithm": "bernoulli_naive_bayes",
        "alpha": 1,
        "class_counts": counts,
        "class_priors": [count / sum(counts) for count in counts],
        "feature_probabilities": probabilities,
    }


def predict(model, vector):
    if len(vector) != len(model["feature_probabilities"][0]) or any(
        value not in (0, 1) for value in vector
    ):
        raise ValueError("Feature vector mismatch")
    logs = [
        math.log(prior)
        + sum(math.log(p if value else 1 - p) for p, value in zip(probabilities, vector))
        for prior, probabilities in zip(model["class_priors"], model["feature_probabilities"])
    ]
    difference = logs[0] - logs[1]
    # Stable logistic transformation of uncalibrated model scores.
    return (
        math.exp(-difference) / (1 + math.exp(-difference))
        if difference >= 0
        else 1 / (1 + math.exp(difference))
    )


def measure(rows, predictions):
    if len(rows) != len(predictions):
        raise ValueError("Prediction count mismatch")
    counts = {name: 0 for name in ("tp", "fp", "tn", "fn")}
    for row, predicted in zip(rows, predictions):
        cell = (
            "tp"
            if predicted and row["label"]
            else "fp"
            if predicted
            else "fn"
            if row["label"]
            else "tn"
        )
        counts[cell] += 1
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))

    def ratio(a, b):
        return a / b if b else None

    return {
        **counts,
        "accuracy": ratio(tp + tn, len(rows)),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
    }


def experiment(path, seed="godeep-malgenome-v1"):
    features, groups, digest, count = load_csv(path)
    splits = split_groups(groups, seed)
    model = fit(splits["train"], len(features))
    majority = int(model["class_counts"][1] > model["class_counts"][0])
    assessments = {}
    predictions = {}
    for split in ("validation", "test"):
        scores = [predict(model, row["features"]) for row in splits[split]]
        decisions = [score >= 0.5 for score in scores]
        assessments[split] = {
            "bernoulli_naive_bayes": measure(splits[split], decisions),
            "majority_class": measure(splits[split], [majority] * len(scores)),
        }
        predictions[split] = [
            {
                "vector_sha256": row["vector_sha256"],
                "label": row["label"],
                "model_score": score,
                "predicted_label": int(predicted),
            }
            for row, score, predicted in zip(splits[split], scores, decisions)
        ]
    report = {
        "schema_version": 1,
        "experiment_version": VERSION,
        "source_sha256": digest,
        "feature_count": len(features),
        "source_rows": count,
        "unique_vectors": len(groups),
        "duplicate_excess_rows": count - len(groups),
        "seed": seed,
        "split_strategy": "stratified_unique_vector_groups_80_10_10_floor",
        "label_mapping": {"B": 0, "S": 1},
        "positive_class": "malware_source_label",
        "threshold": 0.5,
        "threshold_selection": "fixed_before_evaluation",
        "splits": {
            name: {
                "unique_vectors": len(rows),
                "benign": sum(row["label"] == 0 for row in rows),
                "malware": sum(row["label"] == 1 for row in rows),
                "represented_source_rows": sum(row["source_rows"] for row in rows),
            }
            for name, rows in splits.items()
        },
        "metrics": assessments,
        "limitations": [
            "Unique feature vectors are not verified unique APKs",
            "Family and temporal leakage remain unresolved without APK metadata",
            "Metrics are per unique vector on this corpus, not modern APK generalization",
            "Model scores are not calibrated probabilities",
            "Feature categories and extraction equivalence are not established",
            "No feature selection, threshold search or held-out-driven tuning performed",
            "Research artifact only; no production adapter or APK verdict integration",
        ],
    }
    model.update(
        {
            "schema_version": 1,
            "experiment_version": VERSION,
            "source_sha256": digest,
            "features": features,
            "threshold": 0.5,
            "deployment_status": "research_only",
            "calibration": "not_calibrated",
        }
    )
    assignments = [
        {key: value for key, value in row.items() if key != "features"} | {"split": name}
        for name, rows in splits.items()
        for row in rows
    ]
    return {
        "report": report,
        "model": model,
        "assignments": assignments,
        "predictions": predictions,
    }


def main():
    parser = argparse.ArgumentParser(description="Research-only CSV baseline; no APK execution")
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", default="godeep-malgenome-v1")
    args = parser.parse_args()
    try:
        if args.output_dir.exists():
            raise ValueError("Output directory exists")
        result = experiment(args.csv, args.seed)
        args.output_dir.mkdir()  # Never overwrite an existing experiment.
        for name, value in result.items():
            (args.output_dir / (name + ".json")).write_text(
                json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
                encoding="utf-8",
            )
    except (OSError, ValueError, csv.Error):
        parser.exit(
            2,
            "Baseline failed: check CSV values, labels, duplicates and output directory.\n",
        )
    print(json.dumps(result["report"], sort_keys=True))


if __name__ == "__main__":
    main()
