"""Network-free checks for the separate ASI05 challenge runner."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest

from backend.scripts import run_asi05_semantic_challenge as challenge
from integrations.external_evaluator.models import (
    ExternalEvaluationOutcome, ProviderFault, ProviderFaultCode,
)
from testing.evaluation_config import RunnerEvaluationConfig


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Challenge runner tests must not use a process or network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def local_inputs(tmp_path, monkeypatch):
    policy = challenge.base.read_json(challenge.base.FIXTURES / "reviewed_policy_snapshot.json")
    config = RunnerEvaluationConfig.model_validate({
        "mode": "hybrid", "judge_enabled": True, "allow_live_judge": True,
        "max_judge_calls": 1, "require_complete_response_for_semantic": True,
        "pi": {"executable": "never-launched", "provider": "fixture", "model": "fixture",
               "timeout_seconds": 2},
    })
    skill = challenge.base.SkillBundleLoader().load("unexpected_code_execution").identity
    corpus, rows, corpus_sha = challenge.validate_corpus(challenge.CORPUS)
    validation = {
        "corpus_sha256": corpus_sha,
        "request_source_sha256": challenge.source_material_sha256(rows),
        "judge_config_sha256": "test-only-config-hash",
    }
    monkeypatch.setattr(challenge, "validate_environment",
                        lambda *_args: (policy, config, skill, dict(validation)))
    target_dir = tmp_path / "target-data"
    target_dir.mkdir()
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")

    def args(mode, name, *extra):
        return challenge.parser().parse_args([
            f"--{mode}", "--target-data-dir", str(target_dir),
            "--judge-config", str(config_path),
            "--output-dir", str(tmp_path / name), *extra,
        ])
    return tmp_path, args, rows


def test_validate_only_has_nine_rows_and_no_judge(local_inputs, monkeypatch):
    tmp_path, args, _ = local_inputs
    monkeypatch.setattr(challenge.base, "PiEvaluatorProvider",
                        lambda *_: pytest.fail("Pi provider constructed"))
    monkeypatch.setattr(challenge.base.DryRunJudge, "evaluate",
                        lambda *_: pytest.fail("Fake Judge called"))
    summary = challenge.run(args("validate-only", "validated"))
    assert summary["selected_count"] == 9
    assert summary["judge_attempts"] == summary["fake_judge_calls"] == 0
    assert summary["target_request_count"] == 0
    assert summary["provisional_reference_count"] == 4
    assert summary["human_review_selected"] == ["X04", "X06", "X08", "X10"]
    rows = challenge.base.read_json(tmp_path / "validated" / "challenge_results.json")
    assert len(rows) == 9
    assert all(row["judge_request_sha256"] is None and row["resolved_verdict"] is None
               for row in rows)
    default_args = args("validate-only", "default")
    default_args.validate_only = False
    default = challenge.run(default_args)
    assert default["mode"] == "validate-only"
    assert default["judge_attempts"] == default["fake_judge_calls"] == 0


def test_dry_run_uses_production_request_builder_and_keeps_references_out(local_inputs, monkeypatch):
    tmp_path, args, corpus_rows = local_inputs
    monkeypatch.setattr(challenge.base, "PiEvaluatorProvider",
                        lambda *_: pytest.fail("Pi provider constructed"))
    requests = []
    original = challenge.base.DryRunJudge.evaluate

    def capture(self, request):
        requests.append(request)
        return original(self, request)

    monkeypatch.setattr(challenge.base.DryRunJudge, "evaluate", capture)
    summary = challenge.run(args("dry-run", "dry"))
    assert summary["selected_count"] == 9
    assert summary["judge_attempts"] == summary["target_request_count"] == 0
    assert summary["fake_judge_calls"] == len(requests) == 8
    for request, row in zip(requests, (row for row in corpus_rows if row["evaluation_lane"] == "semantic_judge")):
        serialized = request.model_dump_json()
        assert request.testcase.untrusted_input == row["attacker_input"]
        assert request.observation.response_text == row["target_response"]
        assert request.observation.evidence == []
        assert row["reference_rationale"] not in serialized
        assert all(key not in serialized for key in (
            "expected_classification", "expected_verdict", "reference_rationale",
            "required_evidence", "policy_basis", "review_status"))
    rows = challenge.base.read_json(tmp_path / "dry" / "challenge_results.json")
    gate = next(row for row in rows if row["fixture_id"] == "X09")
    assert gate["resolved_verdict"] == "INCONCLUSIVE"
    assert gate["judge_request_sha256"] is None
    assert gate["external_judge_attempts"] == 0
    assert gate["comparison_status"] == "pre_judge_gate_no_external_judge"


def test_execute_requires_gate_and_blocks_human_review(local_inputs):
    _, args, _ = local_inputs
    with pytest.raises(challenge.ChallengeValidationError, match="requires --allow-external-judge"):
        challenge.run(args("execute", "blocked"),
                      provider_factory=lambda: pytest.fail("Provider constructed"))
    with pytest.raises(challenge.ChallengeValidationError, match="pending human review"):
        challenge.run(args("execute", "human", "--allow-external-judge",
                           "--fixtures-select", "X04"),
                      provider_factory=lambda: pytest.fail("Provider constructed"))


class FaultProvider:
    def __init__(self, requests):
        self.requests = requests

    def evaluate(self, request):
        self.requests.append(request)
        return ExternalEvaluationOutcome(
            request_sha256=request.sha256, skill=request.skill, duration_ms=0,
            fault=ProviderFault(code=ProviderFaultCode.TIMEOUT, message="Synthetic fault"),
        )


def test_execute_fake_provider_attempts_only_four_ready_cases_and_zero_for_x09(local_inputs):
    tmp_path, args, _ = local_inputs
    requests = []
    summary = challenge.run(args("execute", "fake-execute", "--allow-external-judge"),
                            provider_factory=lambda: FaultProvider(requests))
    assert summary["selected_count"] == 5
    assert summary["pilot_ready_selected"] == list(challenge.PILOT_READY)
    assert summary["human_review_selected"] == []
    assert summary["judge_attempts"] == len(requests) == 4
    assert summary["target_request_count"] == 0
    assert summary["production_judge_called"] is False
    assert summary["provisional_reference_count"] == 4
    assert summary["comparable_count"] == 0
    rows = challenge.base.read_json(tmp_path / "fake-execute" / "challenge_results.json")
    assert [row["fixture_id"] for row in rows] == ["X02", "X03", "X05", "X07", "X09"]
    assert all(row["external_judge_attempts"] == 1 and row["resolved_verdict"] == "INCONCLUSIVE"
               and row["provider_fault"] == "timeout" for row in rows if row["fixture_id"] != "X09")
    gate = rows[-1]
    assert gate["external_judge_attempts"] == 0
    assert gate["resolved_verdict"] == "INCONCLUSIVE"
    assert gate["actual_classification"] is None


def test_x09_selected_alone_never_constructs_provider(local_inputs):
    tmp_path, args, _ = local_inputs
    summary = challenge.run(args("execute", "gate-only", "--allow-external-judge",
                                 "--fixtures-select", "X09"),
                            provider_factory=lambda: pytest.fail("Provider constructed"))
    assert summary["selected_count"] == 1
    assert summary["judge_attempts"] == summary["target_request_count"] == 0
    assert summary["provisional_reference_count"] == 0
    row = challenge.base.read_json(tmp_path / "gate-only" / "challenge_results.json")[0]
    assert row["resolved_verdict"] == "INCONCLUSIVE"


def test_provenance_hash_ignores_reference_fields_but_binds_gate_state_and_response():
    _, rows, corpus_sha = challenge.validate_corpus(challenge.CORPUS)
    assert corpus_sha == challenge.CORPUS_SHA256
    changed_labels = deepcopy(rows)
    changed_labels[0]["expected_classification"] = "UNCLEAR"
    changed_labels[0]["expected_verdict"] = "INCONCLUSIVE"
    changed_labels[0]["reference_rationale"] = "changed review text"
    changed_labels[0]["review_status"] = "NEEDS_HUMAN_REVIEW"
    assert challenge.source_material_sha256(rows) == challenge.source_material_sha256(changed_labels)
    changed_completeness = deepcopy(rows)
    changed_completeness[-2]["response_complete"] = True
    assert challenge.source_material_sha256(rows) != challenge.source_material_sha256(changed_completeness)
    changed_response = deepcopy(rows)
    changed_response[0]["target_response"] += " changed"
    assert challenge.source_material_sha256(rows) != challenge.source_material_sha256(changed_response)
    changed_prompt = deepcopy(rows)
    changed_prompt[0]["attacker_input"] += " changed"
    assert challenge.source_material_sha256(rows) != challenge.source_material_sha256(changed_prompt)


def test_corpus_hash_mismatch_is_explicit(tmp_path):
    changed = tmp_path / "changed.json"
    changed.write_bytes(challenge.CORPUS.read_bytes() + b" ")
    with pytest.raises(challenge.ChallengeValidationError, match="corpus SHA256 mismatch"):
        challenge.validate_corpus(changed)


def test_policy_skill_and_config_binding_are_checked_without_network(tmp_path, monkeypatch):
    corpus, rows, corpus_sha = challenge.validate_corpus(challenge.CORPUS)
    policy = challenge.base.read_json(challenge.base.FIXTURES / "reviewed_policy_snapshot.json")
    config_bytes = json.dumps({
        "mode": "hybrid", "judge_enabled": True, "allow_live_judge": True,
        "max_judge_calls": 1, "require_complete_response_for_semantic": True,
        "pi": {"executable": "never-launched", "provider": "fixture", "model": "fixture",
               "timeout_seconds": 2},
    }, separators=(",", ":")).encode()
    config_path = tmp_path / "config.json"
    config_path.write_bytes(config_bytes)
    monkeypatch.setattr(challenge.base, "CONFIG_SHA256", sha256(config_bytes).hexdigest())
    target_dir = tmp_path / "target-data"
    target_dir.mkdir()
    (target_dir / "target-catalog.json").write_text("{}", encoding="utf-8")

    class FakeState:
        @staticmethod
        def model_validate(_value):
            return SimpleNamespace(catalog={})

    class FakeStore:
        def __init__(self, _catalog):
            pass

        def load(self, _policy_id):
            return policy

        def status(self, _live):
            return {"response_policy_ready": True}

    monkeypatch.setattr(challenge.base, "ManagedState", FakeState)
    monkeypatch.setattr(challenge.base, "ManagedTargetCatalog", lambda *_: object())
    monkeypatch.setattr(challenge.base, "ASI05PolicyStore", FakeStore)
    args = challenge.parser().parse_args([
        "--validate-only", "--target-data-dir", str(target_dir),
        "--judge-config", str(config_path), "--output-dir", str(tmp_path / "output"),
    ])
    _, config, skill, validation = challenge.validate_environment(args, corpus, corpus_sha, rows)
    assert config.max_judge_calls == 1
    assert validation["policy_binding_verified"] is True
    assert skill.sha256 == corpus["judge_skill_sha256"]

    wrong_policy = {**corpus, "policy_binding": {**corpus["policy_binding"], "target_model": "other"}}
    with pytest.raises(challenge.ChallengeValidationError, match="policy revision or binding mismatch"):
        challenge.validate_environment(args, wrong_policy, corpus_sha, rows)
    wrong_skill = {**corpus, "judge_skill_sha256": "0" * 64}
    with pytest.raises(challenge.ChallengeValidationError, match="Skill identity mismatch"):
        challenge.validate_environment(args, wrong_skill, corpus_sha, rows)
    config_path.write_bytes(config_bytes + b" ")
    with pytest.raises(challenge.ChallengeValidationError, match="configuration SHA256 mismatch"):
        challenge.validate_environment(args, corpus, corpus_sha, rows)
