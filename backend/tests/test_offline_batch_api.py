"""Real Workflow and Reporting APIs, native Runner, mock-only target transport."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import socket
from threading import Event
from time import sleep

import httpx
import pytest

from core.models import (EvaluationConfig, EvaluationRule, EvaluationStatus,
    TestCase as CoreTestCase, TestInput as CoreTestInput)
from reporting.api import create_app as reporting_app
from reporting.repository import load_dataset
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.api import create_app
from workflow.batch import BatchOrchestrator
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchWorkflow, OfflineCaseBinding


BASE = "http://127.0.0.1:8092"
SECRET = "offline-batch-test-secret-" + "x" * 32


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def binding(index):
    marker = {0: ("ALLOWED", EvaluationStatus.PASS),
              1: ("BAD", EvaluationStatus.FAIL)}.get(index, ("UNMATCHED", EvaluationStatus.PASS))
    case = CoreTestCase(id=f"CASE-{index}", name=f"Synthetic case {index}",
        category="goal_hijacking", objective="Classify a harmless synthetic response.",
        attack_module="goal_hijacking", evaluation=EvaluationConfig(rules=[
            EvaluationRule(id="response-marker", type="marker", verdict=marker[1],
                           parameters={"marker": marker[0]})]))
    return OfflineCaseBinding(case, CoreTestInput(id=f"input-{index}",
        prompt=f"Synthetic benign CASE-{index}"))


def setup(tmp_path, *, delay=None, count=5, incomplete_for=None):
    seen = []
    def reply(request):
        body = json.loads(request.content)
        prompt = body["messages"][0]["content"]
        seen.append(prompt)
        index = int(prompt.split("CASE-")[1])
        if delay and index == delay[0]:
            delay[1].set()
            assert delay[2].wait(5)
        if index == 3:
            return httpx.Response(500, text="Synthetic provider error")
        content = {0: "ALLOWED", 1: "BAD", 2: "neutral"}.get(index, "neutral")
        choice = {"message": {"content": content}}
        if index != incomplete_for:
            choice["finish_reason"] = "stop"
        return httpx.Response(200, json={"choices": [choice]})

    config = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "offline-batch-policy", "credential_aliases": {}, "targets": [{
            "id": "synthetic-target", "name": "Synthetic target", "reviewed": True,
            "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
            "protocol": "openai-chat", "models": ["synthetic"],
            "default_model": "synthetic", "timeout_default": 3, "timeout_min": 1,
            "timeout_max": 3}]})
    catalog = TargetCatalog(config)
    row = catalog.public_targets()[0]
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    bindings = [binding(i) for i in range(count)]
    grants = [ExecutionGrant(authorization_id=f"offline-grant-{i}",
        target_id=row["id"], profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"], testcase_id=item.testcase.id,
        asset_sha256=item.asset_sha256, scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
        for i, item in enumerate(bindings) if i != 4]
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(grants=grants), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(reply), output_boundary=output)
    workflow = OfflineBatchWorkflow(dispatcher, bindings, max_cases=10, max_total_requests=10)
    app = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET,
                     batch_service=workflow)
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    return client, headers, workflow, dispatcher, draft, seen


def post(client, path, data, headers):
    return client.post("/api/testing/" + path, base_url=BASE, json=data, headers=headers)


def get(client, path, headers):
    return client.get("/api/testing/" + path, base_url=BASE, headers=headers)


def wait_terminal(client, identity, headers):
    for _ in range(120):
        result = get(client, f"batches/{identity}", headers)
        if result.status_code == 200 and result.json["status"] in {
                "completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            return result.json
        sleep(0.05)
    pytest.fail("Batch did not reach a terminal state")


def test_batch_api_real_runner_reports_progress_and_integrity(tmp_path):
    client, headers, workflow, dispatcher, draft, seen = setup(tmp_path)
    selection = {"target": draft, "testcase_ids": [f"CASE-{i}" for i in range(5)] + ["UNKNOWN"],
                 "total_request_budget": 4, "evaluation_mode": "rule_only"}
    plan = post(client, "batches/preview", selection, headers)
    assert plan.status_code == 200 and plan.json["ready_count"] == 4
    start = selection | {"expected_plan_id": plan.json["plan_id"],
                         "submission_id": "a" * 32, "authorization_confirmed": True}
    accepted = post(client, "batches", start, headers)
    assert accepted.status_code == 202
    identity = accepted.json["batch_run_id"]
    status = wait_terminal(client, identity, headers)
    workflow._worker.join(5)
    assert not workflow._worker.is_alive()
    assert status["processed"] == status["total"] == 6
    assert status["progress_percent"] == 100 and status["target_request_count"] == 4
    assert status["verdict_counts"] == {"PASS": 1, "FAIL": 1, "INCONCLUSIVE": 1, "ERROR": 1}
    assert status["remaining_count"] == 0 and status["current_stage"] is None
    assert status["request_budget_consumed"] == 4 and status["request_count_unknown"] is False
    assert len(seen) == 4 and status["status"] == "partially_completed"
    rows = get(client, f"batches/{identity}/results", headers).json
    assert [r["status"] for r in rows["results"]] == [
        "completed", "completed", "completed", "error", "blocked", "unsupported"]
    assert [r["verdict"] for r in rows["results"]] == [
        "PASS", "FAIL", "INCONCLUSIVE", "ERROR", None, None]
    assert len({r["execution_id"] for r in rows["results"]}) == 6
    assert all(r["report_run_id"] for r in rows["results"][:4])
    assert all(r["report_run_id"] is None for r in rows["results"][4:])
    assert all(r["response_captured"] is True and r["response_complete"] is True
               and r["evidence_provenance"] == "synthetic_mock"
               for r in rows["results"][:3])
    assert all(r["response_captured"] is None and r["response_complete"] is None
               and r["evidence_provenance"] is None for r in rows["results"][4:])
    events = get(client, f"batches/{identity}/events", headers).json["events"]
    stages = [row["stage"] for row in events]
    assert "sending_target_request" in stages and "waiting_for_target_response" in stages
    assert "collecting_evidence" in stages and "running_rule_evaluator" in stages
    assert "saving_report" in stages and "invoking_pi_judge" not in stages
    assert SECRET not in json.dumps(events)
    manifest = tmp_path / "reporting.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(dispatcher.output_root)},
        "controlled_runs_root": "controlled", "reports": [], "verification_jobs": []}))
    reporting = reporting_app(load_dataset(manifest)).test_client()
    for row in rows["results"][:4]:
        run_id = row["report_run_id"]
        report = reporting.get("/api/reports/runs/" + run_id)
        assert report.status_code == 200
        security = report.json["execution"]["security"]
        if row["verdict"] == "ERROR":
            assert security["verdict"] is None and security["historical_status"] == "ERROR"
            assert report.json["execution"]["technical_errors"]
        else:
            assert security["verdict"] == row["verdict"]
            assert report.json["execution"]["observation"]["response_completeness"]["state"] == "complete"
        summary = json.loads((dispatcher.output_root / run_id / "run-summary.json").read_text())
        content = (dispatcher.output_root / run_id / summary["report_file"]).read_bytes()
        assert sha256(content).hexdigest() == row["report_sha256"] == summary["report_sha256"]
        assert summary["input_sha256"] == next(c["input_sha256"] for c in rows["snapshot"]["cases"]
            if c["testcase_id"] == row["testcase_id"])
    assert get(client, f"batches/{identity}", headers).json == status
    assert BatchOrchestrator(workflow.root).state(identity)["status"] == "partially_completed"
    assert len(list(workflow.root.glob("grant-*"))) == 4
    assert post(client, "batches", start, headers).status_code == 409
    assert len(seen) == 4
    assert get(client, f"batches/{identity}", {"Origin": BASE}).status_code == 403
    assert post(client, f"batches/{identity}/cancel", {}, {"Origin": "http://evil.example",
        **{k: v for k, v in headers.items() if k != "Origin"}}).status_code == 403
    assert post(client, f"batches/{identity}/cancel", {},
        {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert get(client, "batches/" + "f" * 32, headers).status_code == 404
    assert workflow.orchestrator.state(identity)["status"] == "partially_completed"


def test_batch_rejects_stale_plan_and_target_without_requests(tmp_path):
    client, headers, _, dispatcher, draft, seen = setup(tmp_path)
    selection = {"target": draft, "testcase_ids": ["CASE-0", "CASE-1", "CASE-2"],
                 "total_request_budget": 3}
    preview = post(client, "batches/preview", selection, headers).json
    start = selection | {"expected_plan_id": "f" * 64,
                         "submission_id": "b" * 32, "authorization_confirmed": True}
    assert post(client, "batches", start, headers).status_code == 409
    stale = start | {"expected_plan_id": preview["plan_id"],
                     "target": draft | {"profile_revision": "e" * 64}}
    assert post(client, "batches", stale, headers).status_code == 409
    assert post(client, "batches", start | {"authorization_confirmed": False}, headers).status_code == 409
    assert post(client, "batches/preview", selection, {"Origin": BASE}).status_code == 403
    default = create_app(dispatcher.catalog, dispatcher=dispatcher,
                         operator_secret=SECRET).test_client()
    default_nonce = default.get("/api/testing/health", base_url=BASE).json
    assert default_nonce["offline_batch_enabled"] is False
    assert post(default, "batches/preview", selection, headers | {
        "X-SecAgent-Validation": default_nonce["validation_nonce"]}).status_code == 403
    assert not seen


def test_cancellation_during_active_case_preserves_report_and_blocks_next(tmp_path):
    active, release = Event(), Event()
    client, headers, workflow, dispatcher, draft, seen = setup(tmp_path,
        delay=(0, active, release), count=3)
    selection = {"target": draft, "testcase_ids": ["CASE-0", "CASE-1", "CASE-2"],
                 "total_request_budget": 3}
    preview = post(client, "batches/preview", selection, headers).json
    try:
        accepted = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
            "submission_id": "c" * 32, "authorization_confirmed": True}, headers)
        assert accepted.status_code == 202
        identity = accepted.json["batch_run_id"]
        assert active.wait(5)
        current = get(client, f"batches/{identity}", headers).json
        assert current["active_testcase_id"] == "CASE-0" and current["processed"] == 0
        assert current["active_testcase_name"] == "Synthetic case 0"
        assert current["active_asi_category"] == "ASI01"
        assert current["current_stage"] in {"sending_target_request", "preparing_execution"}
        duplicate = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
            "submission_id": "d" * 32, "authorization_confirmed": True}, headers)
        assert duplicate.status_code == 409
        cancel = post(client, f"batches/{identity}/cancel", {}, headers)
        assert cancel.status_code == 200 and cancel.json["active_request_cancelled"] is False
        assert cancel.json["active_testcase_id_at_request"] == "CASE-0"
    finally:
        release.set()
    terminal = wait_terminal(client, identity, headers)
    workflow._worker.join(5)
    assert not workflow._worker.is_alive()
    assert terminal["status"] == "cancelled" and terminal["processed"] == 1
    assert len(seen) == 1
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert [r["status"] for r in rows] == ["completed", "cancelled", "cancelled"]
    assert rows[0]["report_run_id"] and all(r["verdict"] is None for r in rows[1:])
    assert (dispatcher.output_root / rows[0]["report_run_id"] / "run-summary.json").is_file()


def test_response_marker_without_complete_observation_is_not_pass(tmp_path):
    client, headers, workflow, _, draft, seen = setup(tmp_path, count=1, incomplete_for=0)
    selection = {"target": draft, "testcase_ids": ["CASE-0"], "total_request_budget": 1}
    preview = post(client, "batches/preview", selection, headers).json
    accepted = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "e" * 32, "authorization_confirmed": True}, headers)
    assert accepted.status_code == 202
    identity = accepted.json["batch_run_id"]
    assert wait_terminal(client, identity, headers)["target_request_count"] == 1
    workflow._worker.join(5)
    row = get(client, f"batches/{identity}/results", headers).json["results"][0]
    assert row["status"] == "completed" and row["verdict"] == "INCONCLUSIVE"
    assert row["response_captured"] is True and row["response_complete"] is None
    assert seen == ["Synthetic benign CASE-0"]


def test_batch_service_rejects_real_transport_and_action_rules(tmp_path):
    _, _, _, dispatcher, _, _ = setup(tmp_path, count=1)
    dispatcher.transport = None
    with pytest.raises(ValueError, match="mock transport"):
        OfflineBatchWorkflow(dispatcher, [binding(0)], max_cases=3, max_total_requests=3)
    unsafe = binding(0)
    case = unsafe.testcase.model_copy(deep=True)
    case.evaluation.rules[0].type = "tool_call"
    with pytest.raises(ValueError, match="response-only"):
        OfflineCaseBinding(case, unsafe.test_input)
