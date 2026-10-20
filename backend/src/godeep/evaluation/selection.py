"""Validation-only research selection; test labels never score or select candidates."""

import argparse
import csv
import json
from pathlib import Path

from godeep.evaluation.classifier import fit, load_csv, measure, predict, split_groups

VERSION = "1.0.0"
THRESHOLDS = (0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 0.9999, 0.999999)
MAX_FPR = 0.05
MIN_RECALL = 0.5


def fit_stump(rows, width):
    """Choose one binary feature by minimum weighted Gini impurity on training only."""
    if not rows or not all(any(row["label"] == label for row in rows) for label in (0, 1)):
        raise ValueError("Stump requires both training classes")
    best = None
    for index in range(width):
        leaves = [[0, 0], [0, 0]]
        for row in rows:
            leaves[row["features"][index]][row["label"]] += 1
        if not all(sum(leaf) for leaf in leaves):
            continue
        impurity = sum(2 * leaf[0] * leaf[1] / sum(leaf) for leaf in leaves) / len(rows)
        if best is None or (impurity, index) < best[:2]:
            best = (impurity, index, leaves)
    if best is None:
        raise ValueError("No nonconstant training feature for stump")
    return {
        "algorithm": "decision_stump",
        "feature_index": best[1],
        "training_impurity": best[0],
        "leaf_class_counts": best[2],
        "leaf_scores": [(leaf[1] + 1) / (sum(leaf) + 2) for leaf in best[2]],
        "alpha": 1,
    }


def stump_score(model, vector):
    return model["leaf_scores"][vector[model["feature_index"]]]


def choose(candidates):
    eligible = [
        item
        for item in candidates
        if item["metrics"]["false_positive_rate"] is not None
        and item["metrics"]["false_positive_rate"] <= MAX_FPR
        and item["metrics"]["recall"] is not None
        and item["metrics"]["recall"] >= MIN_RECALL
    ]
    if not eligible:
        return None
    # Highest recall, then F1, then smallest FPR, deterministic name/threshold tie-break.
    return min(
        eligible,
        key=lambda item: (
            -item["metrics"]["recall"],
            -item["metrics"]["f1"],
            item["metrics"]["false_positive_rate"],
            item["algorithm"],
            item["threshold"],
        ),
    )


def compare(csv_path, seed="godeep-malgenome-v1"):
    features, groups, digest, source_rows = load_csv(csv_path)
    splits = split_groups(groups, seed)
    models = {"bernoulli_naive_bayes": fit(splits["train"], len(features))}
    try:
        models["decision_stump"] = fit_stump(splits["train"], len(features))
    except ValueError:
        pass  # Naive Bayes can still be evaluated if training has no variable feature.
    candidates = []
    for name, model in sorted(models.items()):
        score = predict if name == "bernoulli_naive_bayes" else stump_score
        scores = [score(model, row["features"]) for row in splits["validation"]]
        for threshold in THRESHOLDS:
            candidates.append(
                {
                    "algorithm": name,
                    "threshold": threshold,
                    "metrics": measure(
                        splits["validation"], [value >= threshold for value in scores]
                    ),
                }
            )
    selected = choose(candidates)
    majority = int(sum(row["label"] for row in splits["train"]) > len(splits["train"]) / 2)
    report = {
        "schema_version": 1,
        "selection_version": VERSION,
        "source_sha256": digest,
        "source_rows": source_rows,
        "unique_vectors": len(groups),
        "seed": seed,
        "features": features,
        "selection_split": "validation",
        "test_evaluation": "not_performed",
        "research_objective": {
            "maximum_validation_fpr": MAX_FPR,
            "minimum_validation_recall": MIN_RECALL,
            "rank": "recall_then_f1_then_lowest_fpr_then_name_threshold",
        },
        "threshold_grid": list(THRESHOLDS),
        "validation_size": len(splits["validation"]),
        "validation_class_counts": {
            "benign": sum(row["label"] == 0 for row in splits["validation"]),
            "malware": sum(row["label"] == 1 for row in splits["validation"]),
        },
        "candidates": candidates,
        "selected": selected,
        "selection_status": "validation_candidate_only"
        if selected
        else "no_candidate_meets_objective",
        "majority_validation": measure(
            splits["validation"], [majority] * len(splits["validation"])
        ),
        "limitations": [
            "Validation metrics selected the candidate and are optimistically biased",
            "The previously inspected test set is not reused for selection or reported here",
            "Fresh external evaluation is required before generalization claims",
            "Vector deduplication cannot rule out family or temporal leakage",
            "Research targets are not calibrated operational acceptance criteria",
            "No production promotion, priority-policy changes or extractor integration",
            "Feature scores are not calibrated malware probabilities",
        ],
    }
    artifact = None
    if selected:
        artifact = {
            "schema_version": 1,
            "selection_version": VERSION,
            "source_sha256": digest,
            "features": features,
            "seed": seed,
            "threshold": selected["threshold"],
            "parameters": models[selected["algorithm"]],
            "calibration": "not_calibrated",
            "deployment_status": "validation_candidate_only",
        }
    assignments = [
        {"vector_sha256": row["vector_sha256"], "source_rows": row["source_rows"], "split": name}
        for name, rows in splits.items()
        for row in rows
    ]
    return {"report": report, "candidate": artifact, "assignments": assignments}


def main():
    parser = argparse.ArgumentParser(
        description="Validation-only model comparison; no test scoring"
    )
    parser.add_argument("--csv", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.output_dir.exists():
            raise ValueError("Output directory exists")
        result = compare(args.csv)
        args.output_dir.mkdir()
        for name, value in result.items():
            (args.output_dir / (name + ".json")).write_text(
                json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
                encoding="utf-8",
            )
    except (OSError, ValueError, csv.Error):
        parser.exit(2, "Comparison failed: check CSV values, labels and new output directory.\n")
    print(
        json.dumps(
            {
                key: result["report"][key]
                for key in ("selection_status", "selected", "test_evaluation")
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
