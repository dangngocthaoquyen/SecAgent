"""Validate experiment mechanics without pretending fixture predictions are live."""

import csv
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gh_experiment", ROOT / "backend/scripts/evaluate_gh_dataset.py")
experiment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = experiment
SPEC.loader.exec_module(experiment)


def dataset():
    return experiment.load_dataset(experiment.DEFAULT_DATASET)


def test_dataset_has_balanced_six_groups_and_human_labels_are_not_claimed():
    data = dataset()
    assert len(data.samples) == 30
    assert set(Counter(s.group for s in data.samples).values()) == {5}
    assert len(Counter(s.group for s in data.samples)) == 6
    assert "pending_human_review" in data.provenance


def test_request_and_baseline_are_independent_of_label_and_rationale():
    data = dataset()
    requests, baseline = experiment.prepare(data)
    changed = data.model_copy(deep=True)
    changed.samples[0].proposed_label = experiment.Label(
        classification="UNCLEAR", verdict="INCONCLUSIVE", rationale="Different reviewer opinion.",
    )
    assert experiment.prepare(changed) == (requests, baseline)
    assert all(set(request) == {
        "schema_version", "request_id", "evaluation_type", "testcase",
        "trusted_context", "observation", "expected_labels", "skill",
    } for request in requests)
    assert baseline["GH-E001"] == "FAIL"
    assert baseline["GH-E006"] == "INCONCLUSIVE"  # paraphrase needs provider
    assert baseline["GH-E014"] == "INCONCLUSIVE"  # quote is no longer hard FAIL
    assert baseline["GH-E026"] == "INCONCLUSIVE"  # judge injection is inert data


def test_metrics_include_abstentions_in_attack_recall_and_report_false_pass():
    scores = experiment.metrics(
        {"a": "FAIL", "b": "FAIL", "c": "FAIL", "d": "PASS", "e": "INCONCLUSIVE"},
        {"a": "FAIL", "b": "INCONCLUSIVE", "c": "PASS", "d": "FAIL", "e": "INCONCLUSIVE"},
    )
    assert scores["accuracy"] == 2 / 5
    assert scores["attack_precision"] == 1 / 2
    assert scores["attack_recall"] == 1 / 3
    assert scores["attack_f1"] == pytest.approx(0.4)
    assert scores["false_pass"] == 1 and scores["false_fail"] == 1
    assert scores["inconclusive_rate"] == 2 / 5
    empty_positive = experiment.metrics({"a": "PASS"}, {"a": "PASS"})
    assert empty_positive["attack_recall"] is None


def fixture_predictions(requests):
    # Deliberately NOT gold labels; tests validate plumbing, not judge accuracy.
    return [{
        "sample_id": request["request_id"],
        "request_sha256": experiment.canonical_hash(request),
        "final_verdict": "INCONCLUSIVE",
        "provenance": {
            "provider": "test-fixture", "run_id": "unit-test", "mode": "replay",
            "semantic_invoked": True, "skill_version": request["skill"]["version"],
            "skill_sha256": request["skill"]["sha256"],
        },
    } for request in requests]


def write_predictions(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


@pytest.mark.parametrize("problem", ["missing", "duplicate", "unknown", "request", "skill", "verdict", "mixed_run", "extra"])
def test_comparator_rejects_incomparable_or_invalid_predictions(tmp_path, problem):
    requests, _ = experiment.prepare(dataset())
    rows = fixture_predictions(requests)
    if problem == "missing":
        rows.pop()
    elif problem == "duplicate":
        rows.append(rows[0])
    elif problem == "unknown":
        rows[0]["sample_id"] = "invented"
    elif problem == "request":
        rows[0]["request_sha256"] = "0" * 64
    elif problem == "skill":
        rows[0]["provenance"]["skill_sha256"] = "0" * 64
    elif problem == "verdict":
        rows[0]["final_verdict"] = "SAFE"
    elif problem == "mixed_run":
        rows[0]["provenance"]["mode"] = "live"
    else:
        rows[0]["label"] = "PASS"
    path = tmp_path / "predictions.jsonl"
    write_predictions(path, rows)
    with pytest.raises(ValueError):
        experiment.load_predictions(path, requests)


def test_export_does_not_overwrite_reviews_and_pending_labels_are_rejected(tmp_path):
    path = tmp_path / "review.csv"
    experiment.export_reviews(path, dataset())
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        experiment.export_reviews(path, dataset())
    assert path.read_bytes() == original
    with pytest.raises(ValueError, match="pending"):
        experiment.load_reviews(path, dataset())


@pytest.mark.parametrize("row", ["GH-E001", "GH-E001,,,,,,,extra"])
def test_malformed_review_csv_is_rejected_without_crashing(tmp_path, row):
    path = tmp_path / "malformed.csv"
    path.write_text(",".join(experiment.REVIEW_COLUMNS) + "\n" + row + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="CSV columns"):
        experiment.load_reviews(path, dataset())


@pytest.mark.parametrize("line", ['{"sample_id":"first","sample_id":"second"}', '{"confidence":NaN}'])
def test_ambiguous_json_is_rejected(tmp_path, line):
    path = tmp_path / "malformed.jsonl"
    path.write_text(line, encoding="utf-8")
    requests, _ = experiment.prepare(dataset())
    with pytest.raises(ValueError):
        experiment.load_predictions(path, requests)


def test_review_import_validates_hash_and_mapping(tmp_path):
    path = tmp_path / "reviews.csv"
    data = dataset()
    experiment.export_reviews(path, data)
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        # Simulated review used only to exercise parsing, never shipped as human data.
        row.update(classification="UNCLEAR", verdict="INCONCLUSIVE", rationale="Test fixture.",
                   reviewer="unit-test-fixture", reviewed_at="2026-10-06T12:00:00+07:00")
    def save():
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=experiment.REVIEW_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
    save()
    labels, _ = experiment.load_reviews(path, data)
    assert len(labels) == 30
    rows[0]["request_sha256"] = "0" * 64
    save()
    with pytest.raises(ValueError, match="different request"):
        experiment.load_reviews(path, data)


def test_cli_baseline_then_replay_comparison(tmp_path):
    path, report = tmp_path / "predictions.jsonl", tmp_path / "report.json"
    assert experiment.main(["--output", str(report)]) == 2
    assert not report.exists()
    assert experiment.main(["--allow-proposed", "--output", str(report)]) == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["hybrid"] is None
    assert result["label_source"] == "ai_proposed_not_human_ground_truth"
    requests, _ = experiment.prepare(dataset())
    write_predictions(path, fixture_predictions(requests))
    assert experiment.main(["--allow-proposed", "--hybrid-results", str(path), "--output", str(report)]) == 0
    result = json.loads(report.read_text(encoding="utf-8"))
    assert result["hybrid"]["overall"]["inconclusive_rate"] == 1
    assert all(row["hybrid"]["provenance"]["mode"] == "replay" for row in result["samples"])


def test_bundle_hash_covers_policy_files_and_request_hash_covers_response(tmp_path):
    (tmp_path / "SKILL.md").write_bytes((experiment.SKILLS / "SKILL.md").read_bytes())
    policy = tmp_path / "verdict-policy.md"
    policy.write_text("original", encoding="utf-8")
    before = experiment.skill_identity(tmp_path)
    policy.write_text("changed", encoding="utf-8")
    assert experiment.skill_identity(tmp_path)["sha256"] != before["sha256"]
    requests, _ = experiment.prepare(dataset())
    old = experiment.canonical_hash(requests[0])
    requests[0]["observation"]["response_text"] = "Changed target output."
    assert experiment.canonical_hash(requests[0]) != old
