"""Strict corpus splits and hash-verified evaluation of the initial priority policy."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from godeep.analysis.correlation.risk import VERSION, prioritize

MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RESULT_BYTES = 10 * 1024 * 1024


class Entry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    split: Literal["train", "validation", "test"]
    group_id: str = Field(min_length=1, max_length=200)
    label: Literal["review_required", "routine", "unknown"]
    label_source: str = Field(min_length=1, max_length=500)
    label_basis: str = Field(min_length=1, max_length=1000)
    result_path: str | None = Field(default=None, min_length=1, max_length=500)
    result_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def pair(self):
        if (self.result_path is None) != (self.result_sha256 is None):
            raise ValueError("Result path and digest must be supplied together")
        if (
            not self.group_id.strip()
            or not self.label_source.strip()
            or not self.label_basis.strip()
        ):
            raise ValueError("Group and label provenance cannot be blank")
        if self.result_path:
            path = Path(self.result_path)
            if path.is_absolute() or path.drive or ".." in path.parts:
                raise ValueError("Result path must be a relative path without parent traversal")
        return self


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    target: Literal["analyst_review_priority"]
    dataset_id: str = Field(min_length=1, max_length=200)
    entries: list[Entry] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def splits(self):
        hashes, groups = set(), {}
        for entry in self.entries:
            if entry.input_sha256 in hashes:
                raise ValueError("Duplicate APK hash in corpus")
            hashes.add(entry.input_sha256)
            if entry.group_id in groups and groups[entry.group_id] != entry.split:
                raise ValueError("Group leakage across dataset splits")
            groups[entry.group_id] = entry.split
        return self


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("Non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def bounded(path, limit):
    with path.open("rb") as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Evaluation input exceeds size bound")
    return raw


def ratio(a, b):
    return a / b if b else None


def metrics(counts):
    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    return {
        **counts,
        "precision": ratio(tp, tp + fp),
        "recall_on_assessed": ratio(tp, tp + fn),
        "f1_on_assessed": ratio(2 * tp, 2 * tp + fp + fn),
        "false_positive_rate_on_assessed": ratio(fp, fp + tn),
        "recall_lower_bound_with_positive_abstentions": ratio(
            tp, tp + fn + counts["positive_abstentions"]
        ),
    }


def evaluate(manifest_path, results_root, split="test"):
    if split not in {"train", "validation", "test"}:
        raise ValueError("Unknown split")
    raw = bounded(Path(manifest_path), MAX_MANIFEST_BYTES)
    corpus = Corpus.model_validate(strict_json(raw))
    root = Path(results_root).resolve(strict=True)
    counts = {key: 0 for key in ("tp", "fp", "tn", "fn", "positive_abstentions")}
    rows, profiles = [], set()
    for entry in corpus.entries:
        if entry.split != split:
            continue
        row = {
            "input_sha256": entry.input_sha256,
            "group_id": entry.group_id,
            "label": entry.label,
            "label_source": entry.label_source,
            "label_basis": entry.label_basis,
        }
        data = None
        if entry.result_path:
            path = (root / entry.result_path).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():
                raise ValueError("Result escapes selected root or is not a file")
            result_raw = bounded(path, MAX_RESULT_BYTES)
            if hashlib.sha256(result_raw).hexdigest() != entry.result_sha256:
                raise ValueError("Result digest mismatch")
            data = strict_json(result_raw)
            if (
                not isinstance(data, dict)
                or data.get("schema_version") != 1
                or data.get("adapter") != "risk_review"
                or data.get("adapter_version") != "1.0.0"
                or data.get("input_sha256") != entry.input_sha256
            ):
                raise ValueError("Unsupported or mismatched result identity")
            calculated = prioritize(data)
            if data.get("risk_review") != calculated or calculated["policy_version"] != VERSION:
                raise ValueError("Stored priority differs from current versioned policy")
            profile = {
                "component_versions": data.get("component_versions"),
                "tool_versions": data.get("tool_versions"),
                "feed_sha256": data.get("intelligence", {}).get("feed", {}).get("feed_sha256"),
            }
            profile_hash = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()
            profiles.add(profile_hash)
            row.update(
                {
                    "result_sha256": entry.result_sha256,
                    "score": calculated["score"],
                    "coverage_gaps": calculated["coverage_gaps"],
                    "profile_sha256": profile_hash,
                }
            )
        if entry.label == "unknown":
            row["status"] = "unlabelled"
        elif data is None:
            row["status"] = "abstained_missing_result"
        elif any(
            gap in calculated["coverage_gaps"]
            for gap in (
                "manifest_incomplete",
                "dex_incomplete",
                "grouping_incomplete",
                "resources_incomplete",
            )
        ):
            row["status"] = "abstained_static_coverage"
        else:
            positive = entry.label == "review_required"
            predicted = calculated["score"] >= 20
            cell = (
                "tp"
                if predicted and positive
                else "fp"
                if predicted
                else "fn"
                if positive
                else "tn"
            )
            counts[cell] += 1
            row.update(
                {
                    "status": "assessed",
                    "predicted_review_required": predicted,
                    "confusion_cell": cell,
                }
            )
        if row["status"].startswith("abstained") and entry.label == "review_required":
            counts["positive_abstentions"] += 1
        rows.append(row)
    if not rows:
        raise ValueError("Selected split has no entries")
    assessed = sum(counts[key] for key in ("tp", "fp", "tn", "fn"))
    labelled = sum(row["label"] != "unknown" for row in rows)
    return {
        "schema_version": 1,
        "evaluator_version": "1.0.0",
        "dataset_id": corpus.dataset_id,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "split": split,
        "target": corpus.target,
        "policy_version": VERSION,
        "threshold": 20,
        "selected_entries": len(rows),
        "labelled_entries": labelled,
        "assessed_entries": assessed,
        "coverage_of_labelled": ratio(assessed, labelled),
        "metrics": metrics(counts),
        "mixed_observation_profiles": len(profiles) > 1,
        "profiles": sorted(profiles),
        "rows": rows,
        "limitations": [
            "Measures analyst-review labels, not benign/malicious detection accuracy",
            "Operator-supplied labels and groups are not independently verified",
            "Selective metrics exclude abstentions; always review coverage and abstention counts",
            "Native and dynamic coverage remain unavailable; full assessment is not established",
            "Profile hashes do not establish identical extraction limits or acquisition conditions",
            "No model is trained, threshold tuned, APK executed or data uploaded",
        ],
    }
