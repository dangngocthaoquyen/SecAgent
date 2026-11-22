"""Deterministic regression tests for the Pre-Stage-3 F1 pre-launch _active leak fix."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import threading

import httpx
import pytest

import workflow.offline_batch as offline_batch_mod
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.batch import BatchRejected
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchStart, OfflineBatchWorkflow, OfflineCaseBinding
from core.models import (
    EvaluationConfig,
    EvaluationRule,
    EvaluationStatus,
    TestCase as CoreTestCase,
    TestInput as CoreTestInput,
)


SECRET = "pre-stage3-f1-secret-" + "x" * 32


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def _setup_offline(tmp_path: Path, *, answer=None):
    def default_reply(_request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOWED"}, "finish_reason": "stop"}]})

    config = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "offline-f1-policy",
        "credential_aliases": {},
        "targets": [{
            "id": "synthetic-target",
            "name": "Synthetic target",
            "reviewed": True,
            "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
            "protocol": "openai-chat",
            "models": ["synthetic"],
            "default_model": "synthetic",
            "timeout_default": 3,
            "timeout_min": 1,
            "timeout_max": 3,
        }],
    })
    catalog = TargetCatalog(config)
    row = catalog.public_targets()[0]
    draft = {key: row[key] for key in (
        "profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias",
    )}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    case = CoreTestCase(
        id="CASE-0",
        name="Synthetic F1 case",
        category="goal_hijacking",
        objective="Classify response.",
        attack_module="goal_hijacking",
        evaluation=EvaluationConfig(
            rules=[EvaluationRule(id="marker", type="marker", verdict=EvaluationStatus.PASS, parameters={"marker": "ALLOWED"})]
        ),
    )
    binding = OfflineCaseBinding(case, CoreTestInput(id="input-0", prompt="Synthetic benign CASE-0"))
    grant = ExecutionGrant(
        authorization_id="f1-grant-0",
        target_id=row["id"],
        profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"],
        testcase_id=binding.testcase.id,
        asset_sha256=binding.asset_sha256,
        scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(grants=[grant]),
        output / "runs",
        operator_secret=SECRET,
        transport=httpx.MockTransport(answer or default_reply),
        output_boundary=output,
    )
    workflow = OfflineBatchWorkflow(dispatcher, [binding], max_cases=10, max_total_requests=10)
    return workflow, dispatcher, draft


def _make_start(workflow: OfflineBatchWorkflow, draft: dict, *, submission_id: str, testcase_id: str = "CASE-0") -> OfflineBatchStart:
    selection = workflow.selection_model.model_validate({
        "target": draft,
        "testcase_ids": [testcase_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
    })
    preview = workflow.preview(selection)
    return OfflineBatchStart.model_validate({
        "target": draft,
        "testcase_ids": [testcase_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "expected_plan_id": preview["plan_id"],
        "submission_id": submission_id,
        "authorization_confirmed": True,
    })


def test_f1_plan_construction_failure_does_not_leak_dispatcher_active(tmp_path, monkeypatch):
    workflow, dispatcher, draft = _setup_offline(tmp_path)
    first_item = _make_start(workflow, draft, submission_id="1" * 32)

    original_batch_plan = offline_batch_mod.BatchPlan
    calls = 0

    def fail_first_plan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("injected BatchPlan failure")
        return original_batch_plan(*args, **kwargs)

    monkeypatch.setattr(offline_batch_mod, "BatchPlan", fail_first_plan)

    with pytest.raises(RuntimeError, match="injected BatchPlan failure"):
        workflow.start(first_item)

    assert calls == 1
    assert dispatcher._active is False
    assert workflow._worker is None

    # Existing submission-*.json semantics & anti-replay must remain intact.
    submission_file = workflow.root / f"submission-{'1' * 32}.json"
    assert submission_file.exists()
    record = json.loads(submission_file.read_text(encoding="utf-8"))
    assert set(record.keys()) == {"batch_run_id", "plan_id", "submitted_at"}
    assert record["plan_id"] == first_item.expected_plan_id

    with pytest.raises(BatchRejected, match="Duplicate batch submission"):
        workflow.start(first_item)

    # New valid submission must succeed immediately and run to completion.
    second_item = _make_start(workflow, draft, submission_id="2" * 32)
    started = workflow.start(second_item)
    assert workflow._worker is not None
    workflow._worker.join(timeout=5)
    assert dispatcher._active is False
    state = workflow.orchestrator.state(started["batch_run_id"])
    assert state["status"] == "completed"


def test_f1_case_budget_failure_in_asi01_subclass_recovers_cleanly(tmp_path, monkeypatch):
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="asi01-f1-policy", targets=[]),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="dvaa-researchbot",
        name="DVAA Agent",
        platform_id="dvaa",
        platform_name="DVAA",
        endpoint="http://127.0.0.1:7015/v1/chat/completions",
        protocol="openai-chat",
        model="researchbot",
        timeout_seconds=3,
    )))
    row = catalog.review_profile(ReviewProfile(
        target_id=row["id"],
        profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"],
        endpoint=row["endpoint"],
        protocol=row["protocol"],
        model=row["default_model"],
        capabilities=["chat"],
        authorization_confirmed=True,
    ))
    draft = {key: row[key] for key in (
        "profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias",
    )}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        output / "runs",
        operator_secret=SECRET,
        transport=httpx.MockTransport(lambda _: httpx.Response(
            200,
            json={"choices": [{"message": {"content": "SecAgent is a prototype AI agent security testing system."}, "finish_reason": "stop"}]},
        )),
        output_boundary=output,
    )
    workflow = Asi01BatchWorkflow(dispatcher)
    first_item = _make_start(workflow, draft, submission_id="3" * 32, testcase_id="GH-C01")

    orig_budget = workflow._request_budget_for_case
    attempts = 0

    def fail_once(case_id: str) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("injected budget failure")
        return orig_budget(case_id)

    monkeypatch.setattr(workflow, "_request_budget_for_case", fail_once)

    with pytest.raises(ValueError, match="injected budget failure"):
        workflow.start(first_item)

    assert dispatcher._active is False
    assert (workflow.root / f"submission-{'3' * 32}.json").exists()
    with pytest.raises(BatchRejected, match="Duplicate batch submission"):
        workflow.start(first_item)

    second_item = _make_start(workflow, draft, submission_id="4" * 32, testcase_id="GH-C01")
    started = workflow.start(second_item)
    assert workflow._worker is not None
    workflow._worker.join(timeout=5)
    assert dispatcher._active is False
    assert workflow.orchestrator.state(started["batch_run_id"])["status"] == "completed"


def test_f1_simultaneous_submissions_cannot_both_acquire_execution_ownership(tmp_path):
    entered_transport = threading.Event()
    release_transport = threading.Event()

    def slow_reply(_request):
        entered_transport.set()
        assert release_transport.wait(timeout=5)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOWED"}, "finish_reason": "stop"}]})

    workflow, dispatcher, draft = _setup_offline(tmp_path, answer=slow_reply)
    item_a = _make_start(workflow, draft, submission_id="5" * 32)
    item_b = _make_start(workflow, draft, submission_id="6" * 32)

    barrier = threading.Barrier(2)
    outcomes: list[tuple[str, object]] = []
    outcome_lock = threading.Lock()

    def submit(item: OfflineBatchStart):
        barrier.wait(timeout=5)
        try:
            res = workflow.start(item)
            with outcome_lock:
                outcomes.append(("ok", res))
        except Exception as exc:
            with outcome_lock:
                outcomes.append(("err", exc))

    t1 = threading.Thread(target=submit, args=(item_a,))
    t2 = threading.Thread(target=submit, args=(item_b,))
    t1.start()
    t2.start()

    try:
        assert entered_transport.wait(timeout=5)
        assert dispatcher._active is True
    finally:
        release_transport.set()

    t1.join(timeout=5)
    t2.join(timeout=5)
    if workflow._worker is not None:
        workflow._worker.join(timeout=5)

    ok_results = [val for kind, val in outcomes if kind == "ok"]
    err_results = [val for kind, val in outcomes if kind == "err"]
    assert len(ok_results) == 1
    assert len(err_results) == 1
    assert isinstance(err_results[0], BatchRejected)
    assert "Another controlled execution is active" in str(err_results[0])
    assert dispatcher._active is False
