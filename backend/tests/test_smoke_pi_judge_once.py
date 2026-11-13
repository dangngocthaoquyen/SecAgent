"""Offline checks for the one-shot script; the real Pi process is never started."""

from pathlib import Path
import json
import socket
import subprocess

import pytest

from backend.scripts.smoke_pi_judge_once import (
    RESPONSE, SyntheticExecutor, persist, reporting_detail, synthetic_case,
    synthetic_target,
)
from core.models import Observation, TestInput as Input
from evaluators import ResponseEvaluator
from testing import Runner, RunnerEvaluationConfig
from test_runner_judge_integration import FakeJudge


@pytest.fixture(autouse=True)
def no_process_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Offline preparation must not launch Pi or connect to a target.")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def run_offline(tmp_path: Path, fake: FakeJudge):
    testcase, target, executor = synthetic_case(), synthetic_target(), SyntheticExecutor()
    assert ResponseEvaluator().evaluate(testcase, Observation(
        response_text=RESPONSE, metadata={"execution_success": True})).status.value == "INCONCLUSIVE"
    runner = Runner(executor=executor, judge_provider=fake,
        evaluation_config=RunnerEvaluationConfig(mode="hybrid", judge_enabled=True,
                                                 max_judge_calls=1))
    result = runner.run(testcase, target, Input(id="benign-public-summary",
        prompt="Summarize the public sentence."))
    output = tmp_path / "new"
    output.mkdir()
    report, handoff = persist(output, testcase, target, result, executor, runner)
    return result, runner.last_report, report, reporting_detail(output, handoff), fake, executor


def test_benign_fallback_persists_validated_fake_judge_diagnostics(tmp_path):
    result, native, report, detail, fake, executor = run_offline(tmp_path, FakeJudge(label="ORIGINAL_GOAL"))
    assert result.status.value == "INCONCLUSIVE" and len(fake.calls) == executor.calls == 1
    assert native["judge_budget"]["used"] == 1
    assert native["judge"]["recommendation"] == "PASS"
    assert native["observation"]["response_complete"] is None
    assert detail["security"]["verdict"] == "INCONCLUSIVE"
    assert detail["judge"]["recommendation"] == "PASS"
    assert detail["observation"]["response_preview"] == RESPONSE
    assert report.is_file()


def test_invalid_fake_judge_output_is_provider_fault_not_security_fail(tmp_path):
    result, native, _, detail, fake, executor = run_offline(tmp_path, FakeJudge(mode="invalid"))
    assert result.status.value == "INCONCLUSIVE" and len(fake.calls) == executor.calls == 1
    assert native["judge"]["provider_fault_code"] == "invalid_output"
    assert detail["judge"]["provider_fault_code"] == "invalid_output"
    assert detail["security"]["verdict"] == "INCONCLUSIVE"


def test_manual_opt_in_and_credential_presence_gate_before_output(tmp_path, monkeypatch):
    from backend.scripts.smoke_pi_judge_once import main
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    output = tmp_path / "never-created"
    with pytest.raises(SystemExit):
        main(["--output-dir", str(output)])
    with pytest.raises(SystemExit):
        main(["--allow-real-judge", "--output-dir", str(output)])
    assert not output.exists()


def test_one_shot_main_persists_sanitized_diagnostic_and_rejects_reuse(tmp_path, monkeypatch):
    from backend.scripts import smoke_pi_judge_once as smoke
    fake = FakeJudge(label="ORIGINAL_GOAL")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "offline-test-placeholder")
    monkeypatch.setattr(smoke.shutil, "which", lambda _: "C:/offline/pi.cmd")
    monkeypatch.setattr(smoke, "Runner", lambda **kw: Runner(
        executor=kw["executor"], evaluation_config=kw["evaluation_config"], judge_provider=fake))
    output = tmp_path / "one-shot"
    args = ["--allow-real-judge", "--output-dir", str(output)]
    assert smoke.main(args) == 0
    diagnostic = json.loads((output / "diagnostic.json").read_text(encoding="utf-8"))
    assert diagnostic["smoke_status"] == "valid_recommendation"
    assert diagnostic["provider_evaluate_attempts"] == len(fake.calls) == 1
    assert diagnostic["judge_recommendation"] == "PASS"
    assert diagnostic["final_verdict"] == "INCONCLUSIVE"
    assert diagnostic["reporting_detail_verified"] is True
    assert "offline-test-placeholder" not in json.dumps(diagnostic)
    with pytest.raises(SystemExit):
        smoke.main(args)
    assert len(fake.calls) == 1


def test_reporting_lookup_fault_is_recorded_after_offline_fake_judge(tmp_path, monkeypatch):
    from backend.scripts import smoke_pi_judge_once as smoke
    fake = FakeJudge(label="ORIGINAL_GOAL")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "offline-test-placeholder")
    monkeypatch.setattr(smoke.shutil, "which", lambda _: "C:/offline/pi.cmd")
    monkeypatch.setattr(smoke, "Runner", lambda **kw: Runner(
        executor=kw["executor"], evaluation_config=kw["evaluation_config"], judge_provider=fake))
    monkeypatch.setattr(smoke, "reporting_detail", lambda *args: (_ for _ in ()).throw(ValueError()))
    output = tmp_path / "report-lookup-fault"
    assert smoke.main(["--allow-real-judge", "--output-dir", str(output)]) == 2
    diagnostic = json.loads((output / "diagnostic.json").read_text(encoding="utf-8"))
    assert diagnostic["smoke_status"] == "integration_check_failed"
    assert diagnostic["reporting_detail_verified"] is False
    assert diagnostic["provider_evaluate_attempts"] == len(fake.calls) == 1


def test_provider_fault_diagnostic_does_not_claim_target_fail(tmp_path, monkeypatch):
    from backend.scripts import smoke_pi_judge_once as smoke
    fake = FakeJudge(mode="invalid")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "offline-test-placeholder")
    monkeypatch.setattr(smoke.shutil, "which", lambda _: "C:/offline/pi.cmd")
    monkeypatch.setattr(smoke, "Runner", lambda **kw: Runner(
        executor=kw["executor"], evaluation_config=kw["evaluation_config"], judge_provider=fake))
    output = tmp_path / "provider-fault"
    assert smoke.main(["--allow-real-judge", "--output-dir", str(output)]) == 2
    diagnostic = json.loads((output / "diagnostic.json").read_text(encoding="utf-8"))
    assert diagnostic["smoke_status"] == "provider_fault"
    assert diagnostic["provider_fault_code"] == "invalid_output"
    assert diagnostic["final_verdict"] == "INCONCLUSIVE"
    assert diagnostic["reporting_detail_verified"] is True
    assert diagnostic["provider_evaluate_attempts"] == len(fake.calls) == 1
