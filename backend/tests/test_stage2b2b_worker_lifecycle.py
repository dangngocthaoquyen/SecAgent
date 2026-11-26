"""Stage 2B.2b worker startup consolidation and Thread.start() failure recovery tests."""

import json
import socket
import threading

import httpx
import pytest

from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.batch import BatchRejected
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import (
    GenericImportedBatchWorkflow,
    ImportedBatchSelection,
    ImportedBatchStart,
)
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "stage2b2b-worker-lifecycle-" + "x" * 32


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def _setup_imported(tmp_path):
    def reply(_request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Generic mock reply."}, "finish_reason": "stop"}]},
        )

    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref="stage2b2b-policy", targets=[]),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    saved = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="dvaa-researchbot",
        name="DVAA ResearchBot",
        platform_id="dvaa",
        platform_name="DVAA",
        endpoint="http://127.0.0.1:7015/v1/chat/completions",
        protocol="openai-chat",
        model="researchbot",
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
    envelope = normalize_dataset(json.dumps({"testcases": [{"id": "WL-1", "prompt": "Worker test"}]}).encode(), "wl.json")
    repo.save_dataset(envelope)
    workflow = GenericImportedBatchWorkflow(dispatcher, repo, execution_mode="offline_mock")
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=SECRET,
        local_single_user=True,
        batch_service=workflow,
        dataset_repository=repo,
    )
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    return client, headers, workflow, dispatcher, repo, draft, envelope


def _make_imported_start(workflow, draft, envelope, *, submission_id: str) -> ImportedBatchStart:
    sel = {
        "target": draft,
        "dataset_id": envelope.dataset_id,
        "testcase_ids": [envelope.testcases[0].internal_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "transport_mode": "offline_mock",
    }
    preview = workflow.preview(ImportedBatchSelection.model_validate(sel))
    return ImportedBatchStart.model_validate(sel | {
        "expected_plan_id": preview["plan_id"],
        "submission_id": submission_id,
        "authorization_confirmed": True,
    })


def test_generic_imported_thread_start_failure_recovers_active_and_grants(tmp_path, monkeypatch):
    _, _, workflow, dispatcher, _, draft, envelope = _setup_imported(tmp_path)
    first_item = _make_imported_start(workflow, draft, envelope, submission_id="c" * 32)

    original_start = threading.Thread.start
    attempts = 0

    class SyntheticBaseFailure(BaseException):
        pass

    def fail_first_start(thread_self):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise SyntheticBaseFailure("low-level start failure")
        return original_start(thread_self)

    monkeypatch.setattr(threading.Thread, "start", fail_first_start)

    with pytest.raises(SyntheticBaseFailure, match="low-level start failure"):
        workflow.start(first_item)

    assert attempts == 1
    assert dispatcher._active is False
    assert workflow._active_grant_id is None
    assert workflow._owned_grants == set()
    assert (workflow.root / f"submission-{'c' * 32}.json").exists()

    with pytest.raises(BatchRejected, match="Duplicate batch submission"):
        workflow.start(first_item)

    second_item = _make_imported_start(workflow, draft, envelope, submission_id="d" * 32)
    started = workflow.start(second_item)
    assert workflow._worker is not None
    assert workflow._worker.daemon is False
    workflow._worker.join(timeout=5)
    assert dispatcher._active is False
    assert workflow._active_grant_id is None
    assert workflow._owned_grants == set()

    state = workflow.orchestrator.state(started["batch_run_id"])
    assert state["status"] == "completed"


def test_normal_worker_contract_and_response_shape(tmp_path):
    imp_client, headers, imported_workflow, imported_dispatcher, _, imported_draft, envelope = _setup_imported(tmp_path / "imp")
    imp_sel = {
        "target": imported_draft,
        "testcase_ids": [envelope.testcases[0].internal_id],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    imp_preview = imp_client.post("/api/testing/batches/preview", base_url=BASE, json=imp_sel, headers=headers).json
    imp_started = imp_client.post(
        "/api/testing/batches",
        base_url=BASE,
        json=imp_sel | {
            "expected_plan_id": imp_preview["plan_id"],
            "submission_id": "2" * 32,
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert imp_started.status_code == 202
    assert imported_workflow._worker is not None
    assert imported_workflow._worker.name == "secagent-imported-batch"
    assert imported_workflow._worker.daemon is False
    imported_workflow._worker.join(timeout=5)
    assert set(imp_started.json.keys()) == {
        "workflow_schema_version",
        "batch_run_id",
        "status",
        "plan_id",
        "progress_view",
    }
    assert imp_started.json["workflow_schema_version"] == "1.0.0"
    assert imp_started.json["progress_view"] == f"/api/testing/batches/{imp_started.json['batch_run_id']}"
    assert imported_dispatcher._active is False


def test_started_wait_timeout_keeps_active_fail_closed_until_worker_exits(tmp_path, monkeypatch):
    orig_wait = threading.Event.wait
    _, _, workflow, dispatcher, _, draft, envelope = _setup_imported(tmp_path / "generic_imported")
    item = _make_imported_start(workflow, draft, envelope, submission_id="3" * 32)
    second_item = _make_imported_start(workflow, draft, envelope, submission_id="4" * 32)

    worker_entered = threading.Semaphore(0)
    release_worker = threading.Semaphore(0)
    orig_run = workflow.orchestrator.run

    def delayed_run(*args, **kwargs):
        worker_entered.release()
        assert release_worker.acquire(timeout=5)
        return orig_run(*args, **kwargs)

    def fail_launcher_wait(event_self, timeout=None):
        if timeout in (5, 5.0):
            assert worker_entered.acquire(timeout=5)
            return False
        return orig_wait(event_self, timeout)

    monkeypatch.setattr(workflow.orchestrator, "run", delayed_run)
    monkeypatch.setattr(threading.Event, "wait", fail_launcher_wait)

    try:
        with pytest.raises(BatchRejected, match="Batch state did not become available."):
            workflow.start(item)

        assert workflow._worker is not None and workflow._worker.is_alive()
        assert dispatcher._active is True
        with pytest.raises(BatchRejected, match="Another controlled execution is active."):
            workflow.start(second_item)
    finally:
        release_worker.release()
        if workflow._worker is not None:
            workflow._worker.join(timeout=5)

    assert dispatcher._active is False


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_worker_orchestrator_exception_resets_active_state(tmp_path, monkeypatch):
    _, _, imp_wf, imp_disp, _, imp_draft, envelope = _setup_imported(tmp_path / "imp_err")
    monkeypatch.setattr(imp_wf.orchestrator, "run", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("imported crash")))
    with pytest.raises(BatchRejected, match="Unknown or invalid batch run."):
        imp_wf.start(_make_imported_start(imp_wf, imp_draft, envelope, submission_id="7" * 32))
    assert imp_wf._worker is not None
    imp_wf._worker.join(timeout=5)
    assert imp_disp._active is False
    assert imp_wf._active_grant_id is None
    assert imp_wf._owned_grants == set()
