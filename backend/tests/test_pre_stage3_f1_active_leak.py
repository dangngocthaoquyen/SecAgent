"""Deterministic regression tests for the Pre-Stage-3 F1 pre-launch _active leak fix."""

import json
import socket
import threading

import httpx
import pytest

import workflow.generic_imported_batch as imported_mod
from workflow.admission import AdmissionPolicy
from workflow.batch import BatchRejected
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow, ImportedBatchStart
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


SECRET = "pre-stage3-f1-secret-" + "x" * 32


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def _setup_imported(tmp_path):
    def reply(_request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Generic synthetic response."}, "finish_reason": "stop"}]},
        )

    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="pre-stage3-f1", targets=[]),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    saved = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="local-agent",
        name="Local agent",
        platform_id="lab",
        platform_name="Lab",
        endpoint="http://127.0.0.1:7015/v1/chat/completions",
        protocol="openai-chat",
        model="agent-1",
        timeout_seconds=3,
    )))
    row = catalog.review_profile(ReviewProfile(
        target_id=saved["id"],
        profile_revision=saved["profile_revision"],
        policy_ref=saved["policy_ref"],
        endpoint=saved["endpoint"],
        protocol=saved["protocol"],
        model=saved["default_model"],
        capabilities=["chat"],
        authorization_confirmed=True,
    ))
    draft = {
        k: row[k]
        for k in (
            "profile_revision", "policy_ref", "endpoint", "protocol",
            "method", "request_mapping", "response_parser", "credential_alias",
        )
    } | {"target_id": row["id"], "model": row["default_model"], "timeout_seconds": 3}

    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        output / "runs",
        operator_secret=SECRET,
        transport=httpx.MockTransport(reply),
        output_boundary=output,
    )
    repo = DatasetRepository(tmp_path / "operator-data")
    envelope = normalize_dataset(json.dumps({"testcases": [{"id": "F1-1", "prompt": "Test F1"}]}).encode(), "f1.json")
    repo.save_dataset(envelope)
    workflow = GenericImportedBatchWorkflow(dispatcher, repo, execution_mode="offline_mock")
    return workflow, dispatcher, draft, envelope


def _make_start(workflow, draft, envelope, *, submission_id: str) -> ImportedBatchStart:
    sel = {
        "target": draft,
        "dataset_id": envelope.dataset_id,
        "testcase_ids": [envelope.testcases[0].internal_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "transport_mode": "offline_mock",
    }
    preview = workflow.preview(imported_mod.ImportedBatchSelection.model_validate(sel))
    return ImportedBatchStart.model_validate(sel | {
        "expected_plan_id": preview["plan_id"],
        "submission_id": submission_id,
        "authorization_confirmed": True,
    })


def test_f1_plan_construction_failure_does_not_leak_dispatcher_active(tmp_path, monkeypatch):
    workflow, dispatcher, draft, envelope = _setup_imported(tmp_path)
    original_batch_plan = imported_mod.BatchPlan
    calls = 0

    def fail_first_plan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic plan construction error")
        return original_batch_plan(*args, **kwargs)

    monkeypatch.setattr(imported_mod, "BatchPlan", fail_first_plan)

    with pytest.raises(RuntimeError, match="synthetic plan construction error"):
        workflow.start(_make_start(workflow, draft, envelope, submission_id="1" * 32))

    assert dispatcher._active is False
    started = workflow.start(_make_start(workflow, draft, envelope, submission_id="2" * 32))
    workflow._worker.join(timeout=5)
    assert dispatcher._active is False
    assert workflow.orchestrator.state(started["batch_run_id"])["status"] == "completed"


def test_f1_simultaneous_submissions_cannot_both_acquire_execution_ownership(tmp_path):
    workflow, dispatcher, draft, envelope = _setup_imported(tmp_path)
    item1 = _make_start(workflow, draft, envelope, submission_id="3" * 32)
    item2 = _make_start(workflow, draft, envelope, submission_id="4" * 32)

    barrier = threading.Barrier(2)
    outcomes = []
    errors = []

    def worker(item):
        barrier.wait()
        try:
            outcomes.append(workflow.start(item))
        except BatchRejected as exc:
            errors.append(str(exc))

    t1 = threading.Thread(target=worker, args=(item1,))
    t2 = threading.Thread(target=worker, args=(item2,))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    if workflow._worker is not None:
        workflow._worker.join(timeout=5)

    assert len(outcomes) == 1
    assert len(errors) == 1
    assert dispatcher._active is False
