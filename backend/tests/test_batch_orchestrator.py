"""Synthetic batch foundation; no workflow route, target I/O, or Judge process."""

from hashlib import sha256
import json
from threading import Event, Thread

import pytest

from attack_modules import AttackModuleRegistry, BaseAttackModule
from core.models import (EvaluationConfig, EvaluationResult, EvaluationRule,
    EvaluationStatus, ExecutionResult, TargetInterface, TargetProfile,
    TestCase as CoreTestCase, TestInput as CoreTestInput)
from testing import Runner
from workflow.batch import BatchCase, BatchOrchestrator, BatchPlan, BatchRejected, CaseResult
from workflow.execution_bindings import ExecutionBindingRegistry, NativeExecutionBinding


DIGEST = "a" * 64


def plan(count=4, budget=4):
    return BatchPlan("synthetic-target", DIGEST, "offline-policy", "rule_only",
        tuple(BatchCase(f"CASE-{index}", f"Synthetic case {index}", "ASI01",
            DIGEST, DIGEST, 1) for index in range(count)), budget)


class BenignModule(BaseAttackModule):
    def prepare(self, testcase, test_input):
        return test_input


class SyntheticExecutor:
    def execute(self, target, test_input):
        return ExecutionResult(success=True, status_code=200,
            output_text="synthetic answer", response_complete=True)


class FixedEvaluator:
    def __init__(self, status):
        self.status = status

    def evaluate(self, testcase, observation):
        return EvaluationResult(status=self.status, reason="Synthetic evaluation fixture.")


def native_execution(case, execution_id, stage, root, status):
    testcase = CoreTestCase(id=case.testcase_id, name=case.name, category="synthetic",
        objective="Classify a harmless synthetic answer.", attack_module="benign",
        evaluation=EvaluationConfig(rules=[EvaluationRule(id="fixture", type="marker",
            verdict=EvaluationStatus.FAIL, parameters={"marker": "never"})]))
    target = TargetProfile(id="synthetic-target", name="Synthetic target", target_type="service",
        interface=TargetInterface(type="http", adapter="generic_http", config={}))
    saved = []
    runner = Runner(executor=SyntheticExecutor(), evaluator=FixedEvaluator(status),
        attack_module_registry=AttackModuleRegistry({"benign": BenignModule()}),
        report_sink=saved.append)
    stage("sending_target_request")
    stage("collecting_evidence")
    stage("running_rule_evaluator")
    outcome = runner.run(testcase, target, CoreTestInput(id=execution_id, prompt="Benign synthetic input"))
    assert saved[0]["final_verdict"] == outcome.status.value
    report = root / f"{execution_id}.json"
    report.write_text(json.dumps(saved[0], sort_keys=True), encoding="utf-8")
    return CaseResult("completed", outcome.status.value, 1,
        saved[0]["run_id"], sha256(report.read_bytes()).hexdigest())


def test_batch_runs_native_runner_sequentially_with_separate_reports(tmp_path):
    statuses = (EvaluationStatus.PASS, EvaluationStatus.FAIL,
                EvaluationStatus.INCONCLUSIVE)
    root = tmp_path / "batch"
    orchestrator = BatchOrchestrator(root)
    calls = []

    def execute(case, identity, stage):
        calls.append(case.testcase_id)
        if case.testcase_id == "CASE-3":
            raise RuntimeError("Synthetic executor fault")
        return native_execution(case, identity, stage, tmp_path,
            statuses[int(case.testcase_id.split("-")[1])])

    state = orchestrator.run(plan(), lambda _: "ready", execute)
    assert calls == [f"CASE-{i}" for i in range(4)]
    assert [r["status"] for r in state["results"]] == ["completed"] * 3 + ["error"]
    assert [r["verdict"] for r in state["results"]] == ["PASS", "FAIL", "INCONCLUSIVE", "ERROR"]
    assert state["status"] == "partially_completed" and state["processed"] == 4
    assert state["target_request_count"] == 3 and state["request_budget_consumed"] == 4
    assert state["request_count_unknown"] is True
    assert len({r["execution_id"] for r in state["results"]}) == 4
    for row in state["results"][:3]:
        report = tmp_path / f'{row["execution_id"]}.json'
        assert sha256(report.read_bytes()).hexdigest() == row["report_sha256"]
        assert json.loads(report.read_text())["final_verdict"] == row["verdict"]
    assert BatchOrchestrator(root).state(state["batch_run_id"]) == state
    assert state["snapshot_sha256"] == sha256(json.dumps(state["snapshot"],
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    aggregate_file = root / state["batch_run_id"] / "batch-report.json"
    aggregate = json.loads(aggregate_file.read_text(encoding="utf-8"))
    assert sha256(aggregate_file.read_bytes()).hexdigest() == state["aggregate_report_sha256"]
    assert aggregate["batch_run_id"] == state["batch_run_id"]
    assert [item["report_sha256"] for item in aggregate["cases"]] == [
        item["report_sha256"] for item in state["results"]]
    assert aggregate["cases"][-1]["verdict"] == "ERROR"


def test_batch_admission_and_total_budget_block_without_dispatch(tmp_path):
    orchestrator = BatchOrchestrator(tmp_path / "batch")
    called = []

    def execute(case, identity, stage):
        called.append(case.testcase_id)
        return CaseResult("completed", "INCONCLUSIVE", 1, identity, DIGEST)

    outcome = {"CASE-1": "unsupported", "CASE-2": "skipped", "CASE-3": "blocked"}
    state = orchestrator.run(plan(5, 1), lambda case: outcome.get(case.testcase_id, "ready"), execute)
    assert called == ["CASE-0"]
    assert [r["status"] for r in state["results"]] == [
        "completed", "unsupported", "skipped", "blocked", "blocked"]
    assert state["results"][-1]["reason"] == "batch_request_budget_exhausted"
    assert state["target_request_count"] == state["request_budget_consumed"] == 1
    assert state["processed"] == state["total"] == 5
    assert all(r["verdict"] is None for r in state["results"][1:])


def test_cancellation_preserves_completed_record_and_no_new_dispatch(tmp_path):
    root = tmp_path / "batch"
    orchestrator = BatchOrchestrator(root)
    active, release = Event(), Event()
    results = []
    run_id = "b" * 32

    def execute(case, identity, stage):
        if case.testcase_id == "CASE-1":
            active.set()
            assert release.wait(5)
        return CaseResult("completed", "PASS", 1, identity, DIGEST)

    worker = Thread(target=lambda: results.append(orchestrator.run(
        plan(), lambda _: "ready", execute, batch_run_id=run_id)))
    worker.start()
    assert active.wait(5)
    current = orchestrator.state(run_id)
    assert current["processed"] == 1 and current["active_testcase_id"] == "CASE-1"
    orchestrator.cancel_remaining(run_id)
    marker = json.loads((root / run_id / "cancel-requested.json").read_text())
    assert marker["active_testcase_id"] == "CASE-1"
    release.set()
    worker.join(5)
    assert not worker.is_alive()
    state = results[0]
    assert state["status"] == "cancelled" and state["processed"] == 2
    assert [r["status"] for r in state["results"]] == [
        "completed", "completed", "cancelled", "cancelled"]
    assert [r["verdict"] for r in state["results"][2:]] == [None, None]
    with pytest.raises(BatchRejected):
        orchestrator.run(plan(), lambda _: "ready", execute, batch_run_id=run_id)


def test_duplicate_and_concurrent_batch_claims_fail_closed(tmp_path):
    root = tmp_path / "batch"
    first = BatchOrchestrator(root)
    second = BatchOrchestrator(root)
    active, release = Event(), Event()
    completed = []

    def execute(case, identity, stage):
        active.set()
        assert release.wait(5)
        return CaseResult("completed", "INCONCLUSIVE", 1, identity, DIGEST)

    worker = Thread(target=lambda: completed.append(first.run(
        plan(1), lambda _: "ready", execute, batch_run_id="c" * 32)))
    worker.start()
    assert active.wait(5)
    with pytest.raises(BatchRejected, match="Another batch"):
        second.run(plan(1), lambda _: "ready", execute, batch_run_id="d" * 32)
    release.set()
    worker.join(5)
    assert completed[0]["status"] == "completed"
    assert not (root / ".active-batch").exists()
    with pytest.raises(BatchRejected, match="already claimed"):
        second.run(plan(1), lambda _: "ready", execute, batch_run_id="c" * 32)


def test_invalid_identity_and_result_contracts(tmp_path):
    with pytest.raises(ValueError):
        BatchPlan("synthetic-target", DIGEST, "policy", "rule_only",
            (plan(1).cases[0], plan(1).cases[0]), 2)
    with pytest.raises(ValueError):
        CaseResult("error", "FAIL", 0)
    with pytest.raises(BatchRejected):
        BatchOrchestrator(tmp_path).state("../other")


def test_trusted_binding_registry_does_not_dispatch_unknown_or_changed_cases():
    calls = []
    def execute(selection, case, execution_id, stage):
        calls.append(case.testcase_id)
        return CaseResult("completed", "INCONCLUSIVE", 1, execution_id, DIGEST)
    binding = NativeExecutionBinding("GH-001", "openai-chat", "generic_http",
        ("chat",), "complete_response_text", None, ("GH-C01:PASS",), 1, execute)
    registry = ExecutionBindingRegistry((binding,))
    assert registry.get("GH-001").prerequisites == ("GH-C01:PASS",)
    assert registry.get("GH-002") is None
    registry.execute(None, BatchCase("GH-001", "Attack", "ASI01", DIGEST, DIGEST, 1),
        "a" * 32, lambda _: None)
    assert calls == ["GH-001"]
    with pytest.raises(ValueError):
        registry.execute(None, BatchCase("GH-002", "Unknown", "ASI01", DIGEST, DIGEST, 1),
            "b" * 32, lambda _: None)
    with pytest.raises(ValueError):
        registry.execute(None, BatchCase("GH-001", "Changed", "ASI01", DIGEST, DIGEST, 2),
            "c" * 32, lambda _: None)
    assert calls == ["GH-001"]


def test_dead_owner_is_recorded_interrupted_without_restarting_cases(tmp_path):
    root = tmp_path / "batch"
    identity = "e" * 32
    directory = root / identity
    directory.mkdir(parents=True)
    (directory / "state.json").write_text(json.dumps({"status": "running",
        "batch_run_id": identity, "active_testcase_id": "CASE-0",
        "events": [], "results": [], "processed": 0, "total": 1}))
    (root / ".active-batch").write_text(json.dumps({"batch_run_id": identity,
        "pid": 2147483647}))
    recovered = BatchOrchestrator(root)
    state = recovered.state(identity)
    assert state["status"] == "interrupted"
    assert state["processed"] == 0 and state["active_testcase_id"] is None
    assert state["events"][-1]["stage"] == "interrupted"
    assert not (root / ".active-batch").exists()
