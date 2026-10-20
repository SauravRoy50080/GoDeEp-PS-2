"""Offline evaluator CLI; explicit local inputs and exclusive report creation."""

import argparse
import json
from pathlib import Path

from godeep.evaluation.priority import evaluate


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate recorded priority results; no APK execution"
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--results-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--split", choices=("train", "validation", "test"), default="test")
    args = parser.parse_args()
    try:
        report = evaluate(args.manifest, args.results_root, args.split)
        raw = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)
        with args.output.open("x", encoding="utf-8") as destination:
            destination.write(raw + "\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.exit(
            2,
            "Evaluation failed: check input schema, hashes, coverage structure and output path.\n",
        )
    print(f"Evaluation report saved: {args.output}")


if __name__ == "__main__":
    main()
