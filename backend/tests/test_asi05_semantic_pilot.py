"""Network-free CLI tests for the prepared ASI05 production Judge pilot."""

from hashlib import sha256
import json
import socket
import subprocess

import pytest

from backend.scripts import run_asi05_semantic_pilot as pilot
from integrations.external_evaluator.models import (
    ExternalEvaluationOutcome, ExternalEvaluationResult, ProviderFault, ProviderFaultCode,
)
from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider, ProcessOutput
from testing.evaluation_config import RunnerEvaluationConfig


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Semantic pilot unit tests must not use a process or the network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def local_inputs(tmp_path, monkeypatch):
    rows = pilot.read_json(pilot.FIXTURES / "semantic_cases.json")["cases"]
    policy = pilot.read_json(pilot.FIXTURES / "reviewed_policy_snapshot.json")
    config = RunnerEvaluationConfig.model_validate({
        "mode": "hybrid", "judge_enabled": True, "allow_live_judge": True,
        "max_judge_calls": 1, "require_complete_response_for_semantic": True,
        "pi": {"executable": "never-launched", "provider": "fixture", "model": "fixture",
               "timeout_seconds": 2},
    })
    skill = pilot.SkillBundleLoader().load("unexpected_code_execution").identity
    validation = {
        "fixture_sha256": sha256((pilot.FIXTURES / "semantic_cases.json").read_bytes()).hexdigest(),
        "request_source_sha256": pilot.request_material_sha256(rows),
        "fixture_review": {case_id: {
            "status": "NEEDS_HUMAN_REVIEW" if case_id in pilot.REVIEW_REASONS else "PROVISIONAL_REFERENCE",
            "reason": pilot.REVIEW_REASONS.get(case_id),
        } for case_id in pilot.EXPECTED_IDS},
    }
    monkeypatch.setattr(pilot, "validate_inputs", lambda _args: (rows, policy, config, skill, dict(validation)))
    target_dir = tmp_path / "target-data"
    target_dir.mkdir()
    config_path = tmp_path / "judge.json"
    config_path.write_text("{}", encoding="utf-8")

    def args(mode, name, *extra):
        return pilot.parser().parse_args([
            *([f"--{mode}"] if mode else []), "--target-data-dir", str(target_dir),
            "--judge-config", str(config_path), "--output-dir", str(tmp_path / name), *extra,
        ])
    return tmp_path, args


def test_validate_only_and_default_never_construct_judge(local_inputs, monkeypatch):
    tmp_path, args = local_inputs
    monkeypatch.setattr(pilot, "PiEvaluatorProvider", lambda *_: pytest.fail("Pi constructed"))
    monkeypatch.setattr(pilot.DryRunJudge, "evaluate", lambda *_: pytest.fail("Fake Judge called"))
    explicit = pilot.run(args("validate-only", "validated"))
    default_args = args(None, "default")
    assert pilot.main(["--target-data-dir", str(default_args.target_data_dir),
                       "--judge-config", str(default_args.judge_config),
                       "--output-dir", str(default_args.output_dir)]) == 0
    default = pilot.read_json(tmp_path / "default" / "semantic_summary.json")
    assert explicit["selected_count"] == default["selected_count"] == 7
    assert explicit["judge_attempts"] == default["judge_attempts"] == 0
    assert explicit["target_request_count"] == 0
    rows = pilot.read_json(tmp_path / "validated" / "semantic_results.json")
    assert all(row["actual_classification"] is None and row["resolved_verdict"] is None for row in rows)
    assert explicit["needs_human_review"] == ["D1", "D2", "E"]


def test_dry_run_builds_request_without_reference_labels(local_inputs, monkeypatch):
    tmp_path, args = local_inputs
    monkeypatch.setattr(pilot, "PiEvaluatorProvider", lambda *_: pytest.fail("Pi constructed"))
    requests = []
    original = pilot.DryRunJudge.evaluate

    def capture(self, request):
        requests.append(request)
        return original(self, request)

    monkeypatch.setattr(pilot.DryRunJudge, "evaluate", capture)
    summary = pilot.run(args("dry-run", "dry"))
    assert summary["selected_count"] == len(requests) == 7
    assert summary["judge_attempts"] == summary["target_request_count"] == 0
    corpus = pilot.read_json(pilot.FIXTURES / "semantic_cases.json")
    for request, row in zip(requests, corpus["cases"]):
        serialized = request.model_dump_json()
        assert request.testcase.untrusted_input == row["attacker_input"]
        assert request.observation.response_text == row["response"]
        assert request.observation.evidence == []
        assert row["rationale"] not in serialized
        assert all(key not in serialized for key in (
            "expected_classification", "expected_verdict", "reference_review_status",
            "agreement_with_reference"))
    results = pilot.read_json(tmp_path / "dry" / "semantic_results.json")
    assert all(row["resolved_verdict"] is None for row in results)


def test_request_source_identity_ignores_reference_labels_and_rationales():
    rows = pilot.read_json(pilot.FIXTURES / "semantic_cases.json")["cases"]
    changed = [{**row, "classification": "UNCLEAR", "verdict": "INCONCLUSIVE",
                "citation": "changed-reference-citation", "rationale": "changed-reference-rationale"}
               for row in rows]
    assert pilot.request_material_sha256(rows) == pilot.request_material_sha256(changed)


class SpyProvider:
    def __init__(self, *, bad_citation=False, fault=None):
        self.requests = []
        self.bad_citation = bad_citation
        self.fault = fault

    def evaluate(self, request):
        self.requests.append(request)
        if self.fault:
            return ExternalEvaluationOutcome(request_sha256=request.sha256, skill=request.skill,
                duration_ms=0, fault=ProviderFault(code=self.fault, message="Synthetic fault"))
        response = request.observation.response_text
        citation = "not-in-response" if self.bad_citation else response
        return ExternalEvaluationOutcome(request_sha256=request.sha256, skill=request.skill,
            duration_ms=0, result=ExternalEvaluationResult(
                classification="PROHIBITED_COMMAND_ARTIFACT", verdict="FAIL", confidence=0.9,
                reason="Synthetic recommendation only.",
                evidence=[{"type": "response_span", "value": citation}]))


@pytest.mark.parametrize("fixture_id", ["A", "I"])
def test_execute_path_selects_each_fixture_once_without_target(local_inputs, fixture_id):
    tmp_path, args = local_inputs
    providers = []

    def factory():
        provider = SpyProvider()
        providers.append(provider)
        return provider

    summary = pilot.run(args("execute", f"pilot-{fixture_id}", "--allow-external-judge",
                             "--fixtures-select", fixture_id), provider_factory=factory)
    assert summary["selected_count"] == summary["judge_attempts"] == 1
    assert summary["target_request_count"] == 0
    assert len(providers) == len(providers[0].requests) == 1
    result = pilot.read_json(tmp_path / f"pilot-{fixture_id}" / "semantic_results.json")[0]
    assert result["fixture_id"] == fixture_id
    assert result["resolved_verdict"] == "FAIL"
    assert result["agreement_with_reference"] is True
    assert result["exact_response_citation"] == [providers[0].requests[0].observation.response_text]


def test_execute_requires_explicit_judge_authorization(local_inputs):
    _, args = local_inputs
    with pytest.raises(pilot.PilotValidationError, match="requires --allow-external-judge"):
        pilot.run(args("execute", "blocked", "--fixtures-select", "A"),
                  provider_factory=lambda: pytest.fail("Provider constructed"))


def test_invalid_citation_and_provider_fault_are_not_agreement(local_inputs):
    tmp_path, args = local_inputs
    bad = pilot.run(args("execute", "bad-cite", "--allow-external-judge",
                         "--fixtures-select", "A"), provider_factory=lambda: SpyProvider(bad_citation=True))
    row = pilot.read_json(tmp_path / "bad-cite" / "semantic_results.json")[0]
    assert bad["comparable_count"] == 0
    assert row["resolved_verdict"] == "INCONCLUSIVE"
    assert row["comparison_status"] == "invalid_citation"
    assert row["provider_fault"] == "invalid_output"

    fault = pilot.run(args("execute", "timeout", "--allow-external-judge",
                           "--fixtures-select", "A"),
                      provider_factory=lambda: SpyProvider(fault=ProviderFaultCode.TIMEOUT))
    row = pilot.read_json(tmp_path / "timeout" / "semantic_results.json")[0]
    assert fault["comparable_count"] == 0
    assert row["resolved_verdict"] == "INCONCLUSIVE"
    assert row["comparison_status"] == "provider_fault"
    assert row["agreement_with_reference"] is None


def test_nonzero_exit_diagnostic_is_reported_without_raw_process_output(local_inputs):
    tmp_path, args = local_inputs
    secret = "FAKE_SECRET_SENTINEL"

    class FakeProcess:
        def run(self, *_args, **_kwargs):
            return ProcessOutput(exit_code=1, stdout=secret.encode(),
                                 stderr=b"opaque error: " + secret.encode())

    def factory():
        return PiEvaluatorProvider(PiEvaluatorConfig(
            executable="never-launched", provider="fixture", model="fixture",
            timeout_seconds=2), process_runner=FakeProcess())

    summary = pilot.run(args("execute", "diagnostic", "--allow-external-judge",
                             "--fixtures-select", "A"),
                        provider_factory=factory)
    row = pilot.read_json(tmp_path / "diagnostic" / "semantic_results.json")[0]
    assert summary["judge_attempts"] == 1
    assert summary["target_request_count"] == 0
    assert row["provider_fault"] == "nonzero_exit"
    assert row["provider_diagnostic_code"] == "unknown"
    assert row["resolved_verdict"] == "INCONCLUSIVE"
    assert row["actual_classification"] is None
    assert "stderr" not in row["structured_judge_outcome"]
    assert "stdout" not in row["structured_judge_outcome"]
    for artifact in ("semantic_results.json", "semantic_results.csv", "semantic_summary.json"):
        assert secret not in (tmp_path / "diagnostic" / artifact).read_text(encoding="utf-8")


def test_ambiguous_reference_excluded_from_agreement_rate(local_inputs):
    tmp_path, args = local_inputs
    summary = pilot.run(args("execute", "ambiguous", "--allow-external-judge",
                             "--fixtures-select", "D1,D2,E"), provider_factory=SpyProvider)
    assert summary["selected_count"] == summary["judge_attempts"] == 3
    assert summary["provisional_reference_count"] == summary["comparable_count"] == 0
    assert summary["provisional_agreement_rate"] is None
    rows = pilot.read_json(tmp_path / "ambiguous" / "semantic_results.json")
    assert all(row["reference_review_status"] == "NEEDS_HUMAN_REVIEW"
               and row["comparison_status"] == "ambiguous_reference_label" for row in rows)


def test_snapshot_hash_failure_is_explicit(tmp_path):
    source = pilot.FIXTURES / "reviewed_policy_snapshot.json"
    changed = tmp_path / "changed-policy.json"
    changed.write_bytes(source.read_bytes() + b" ")
    cli = pilot.parser().parse_args(["--validate-only", "--policy-snapshot", str(changed),
        "--target-data-dir", str(tmp_path), "--judge-config", str(tmp_path / "unused.json"),
        "--output-dir", str(tmp_path / "unused-output")])
    with pytest.raises(pilot.PilotValidationError, match="snapshot SHA256 mismatch"):
        pilot.validate_inputs(cli)


def test_corpus_hash_failure_is_explicit(tmp_path):
    source = pilot.FIXTURES / "semantic_cases.json"
    changed = tmp_path / "changed-corpus.json"
    changed.write_bytes(source.read_bytes() + b" ")
    cli = pilot.parser().parse_args(["--validate-only", "--fixtures", str(changed),
        "--target-data-dir", str(tmp_path), "--judge-config", str(tmp_path / "unused.json"),
        "--output-dir", str(tmp_path / "unused-output")])
    with pytest.raises(pilot.PilotValidationError, match="corpus SHA256 mismatch"):
        pilot.validate_inputs(cli)
