"""Stage 2B.2b worker startup consolidation and Thread.start() failure recovery tests."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import threading

import httpx
import pytest

from core.models import (
    EvaluationConfig,
    EvaluationRule,
    EvaluationStatus,
    TestCase as CoreTestCase,
    TestInput as CoreTestInput,
)
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.api import create_app
from workflow.asi01_batch import Asi01BatchWorkflow
from workflow.batch import BatchRejected
from workflow.catalog import TargetCatalog
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow, ImportedBatchSelection, ImportedBatchStart
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchStart, OfflineBatchWorkflow, OfflineCaseBinding
from workflow.toolbot_lab_batch import LAB_ENDPOINT, LAB_ID, LAB_MODEL, ToolBotLabBatchWorkflow


BASE = "http://127.0.0.1:8092"
SECRET = "stage2b2b-worker-lifecycle-" + "x" * 32
CODEBOT_JSON = Path(__file__).parent / "fixtures/datasets/codebot_asi02.synthetic.json"


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def _make_offline_binding(index: int = 0) -> OfflineCaseBinding:
    marker = ("ALLOWED", EvaluationStatus.PASS) if index == 0 else ("BAD", EvaluationStatus.FAIL)
    case = CoreTestCase(
        id=f"CASE-{index}",
        name=f"Synthetic case {index}",
        category="goal_hijacking",
        objective="Classify a harmless synthetic response.",
        attack_module="goal_hijacking",
        evaluation=EvaluationConfig(
            rules=[EvaluationRule(id="response-marker", type="marker", verdict=marker[1], parameters={"marker": marker[0]})]
        ),
    )
    return OfflineCaseBinding(case, CoreTestInput(id=f"input-{index}", prompt=f"Synthetic benign CASE-{index}"))


def _setup_offline(tmp_path: Path):
    def reply(_request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOWED"}, "finish_reason": "stop"}]})

    config = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "offline-batch-policy",
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
    bindings = [_make_offline_binding(0)]
    grants = [ExecutionGrant(
        authorization_id="offline-grant-0",
        target_id=row["id"],
        profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"],
        testcase_id=bindings[0].testcase.id,
        asset_sha256=bindings[0].asset_sha256,
        scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )]
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(grants=grants),
        output / "runs",
        operator_secret=SECRET,
        transport=httpx.MockTransport(reply),
        output_boundary=output,
    )
    workflow = OfflineBatchWorkflow(dispatcher, bindings, max_cases=10, max_total_requests=10)
    return workflow, dispatcher, draft


def _setup_managed_dispatcher(
    tmp_path: Path,
    *,
    policy_ref: str,
    target_id: str,
    protocol: str,
    endpoint: str,
    model: str,
    capabilities: list[str],
    transport_fn,
):
    catalog = ManagedTargetCatalog(
        CatalogConfig(catalog_schema_version="1.0.0", policy_ref=policy_ref, targets=[]),
        tmp_path / "operator-data",
        local_single_user=True,
    )
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id=target_id,
        name="Synthetic Agent",
        platform_id="dvaa",
        platform_name="DVAA",
        endpoint=endpoint,
        protocol=protocol,
        model=model,
        timeout_seconds=3,
    )))
    row = catalog.review_profile(ReviewProfile(
        target_id=row["id"],
        profile_revision=row["profile_revision"],
        policy_ref=row["policy_ref"],
        endpoint=row["endpoint"],
        protocol=row["protocol"],
        model=row["default_model"],
        capabilities=capabilities,
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
        transport=httpx.MockTransport(transport_fn),
        output_boundary=output,
    )
    return catalog, dispatcher, draft


def _setup_imported(tmp_path: Path):
    def answer(_request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "I cannot perform that sensitive action."}, "finish_reason": "stop"}]
        })

    catalog, dispatcher, draft = _setup_managed_dispatcher(
        tmp_path,
        policy_ref="imported-reviewed-lab",
        target_id="dvaa-researchbot",
        protocol="openai-chat",
        endpoint="http://127.0.0.1:7015/v1/chat/completions",
        model="researchbot",
        capabilities=["chat"],
        transport_fn=answer,
    )
    repo = DatasetRepository(tmp_path / "operator-data")
    envelope = normalize_dataset(CODEBOT_JSON.read_bytes(), "testcases_dvaa_codebot_asi02.json")
    repo.save_dataset(envelope)
    workflow = GenericImportedBatchWorkflow(dispatcher, repo)
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=SECRET,
        local_single_user=True,
        batch_service=workflow,
        dataset_repository=repo,
    )
    client = app.test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    headers = {
        "Origin": BASE,
        "X-SecAgent-Validation": health["validation_nonce"],
        "X-SecAgent-Operator": SECRET,
    }
    return client, headers, workflow, dispatcher, repo, draft, envelope


def _make_offline_start(workflow: OfflineBatchWorkflow, draft: dict, *, submission_id: str, testcase_ids=("CASE-0",), budget=1):
    selection = workflow.selection_model.model_validate({
        "target": draft,
        "testcase_ids": list(testcase_ids),
        "total_request_budget": budget,
        "evaluation_mode": "rule_only",
    })
    preview = workflow.preview(selection)
    return OfflineBatchStart.model_validate({
        "target": draft,
        "testcase_ids": list(testcase_ids),
        "total_request_budget": budget,
        "evaluation_mode": "rule_only",
        "expected_plan_id": preview["plan_id"],
        "submission_id": submission_id,
        "authorization_confirmed": True,
    })


def _make_imported_start(workflow: GenericImportedBatchWorkflow, draft: dict, envelope, *, submission_id: str, budget=1):
    ids = [envelope.testcases[0].internal_id]
    selection = ImportedBatchSelection.model_validate({
        "target": draft,
        "dataset_id": envelope.dataset_id,
        "testcase_ids": ids,
        "total_request_budget": budget,
        "evaluation_mode": "rule_only",
    })
    preview = workflow.preview(selection)
    return ImportedBatchStart.model_validate({
        "target": draft,
        "dataset_id": envelope.dataset_id,
        "testcase_ids": ids,
        "total_request_budget": budget,
        "evaluation_mode": "rule_only",
        "expected_plan_id": preview["plan_id"],
        "submission_id": submission_id,
        "authorization_confirmed": True,
    })


def test_offline_batch_thread_start_failure_recovers_active_state(tmp_path, monkeypatch):
    workflow, dispatcher, draft = _setup_offline(tmp_path)
    first_item = _make_offline_start(workflow, draft, submission_id="a" * 32)

    original_start = threading.Thread.start
    attempts = 0

    def fail_first_start(thread_self):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("can't start new thread")
        return original_start(thread_self)

    monkeypatch.setattr(threading.Thread, "start", fail_first_start)

    with pytest.raises(RuntimeError, match="can't start new thread"):
        workflow.start(first_item)

    assert attempts == 1
    assert dispatcher._active is False
    # Durable submission claim must remain fail-closed so the same submission_id stays rejected.
    assert (workflow.root / f"submission-{'a' * 32}.json").exists()
    with pytest.raises(BatchRejected, match="Duplicate batch submission"):
        workflow.start(first_item)

    second_item = _make_offline_start(workflow, draft, submission_id="b" * 32)
    started = workflow.start(second_item)
    assert workflow._worker is not None
    assert isinstance(workflow._worker, threading.Thread)
    assert workflow._worker.daemon is False
    workflow._worker.join(timeout=5)
    assert workflow._worker.is_alive() is False
    assert dispatcher._active is False

    state = workflow.orchestrator.state(started["batch_run_id"])
    assert state["status"] == "completed"
    report_run_id = state["results"][0]["report_run_id"]
    assert report_run_id is not None
    run_summary_path = dispatcher.output_root / report_run_id / "run-summary.json"
    assert run_summary_path.exists()
    summary_data = json.loads(run_summary_path.read_text(encoding="utf-8"))
    assert (dispatcher.output_root / report_run_id / summary_data["report_file"]).exists()


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


def test_asi01_and_toolbot_subclass_thread_start_failure_recovery(tmp_path, monkeypatch):
    _, asi01_dispatcher, asi01_draft = _setup_managed_dispatcher(
        tmp_path / "asi01",
        policy_ref="asi01-reviewed-lab",
        target_id="dvaa-researchbot",
        protocol="openai-chat",
        endpoint="http://127.0.0.1:7015/v1/chat/completions",
        model="researchbot",
        capabilities=["chat"],
        transport_fn=lambda _: httpx.Response(
            200,
            json={"choices": [{"message": {"content": "SecAgent is a prototype AI agent security testing system."}, "finish_reason": "stop"}]},
        ),
    )
    asi01_workflow = Asi01BatchWorkflow(asi01_dispatcher)
    asi01_sel = asi01_workflow.selection_model.model_validate({
        "target": asi01_draft,
        "testcase_ids": ["GH-C01"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
    })
    asi01_preview = asi01_workflow.preview(asi01_sel)
    asi01_item = OfflineBatchStart.model_validate({
        "target": asi01_draft,
        "testcase_ids": ["GH-C01"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "expected_plan_id": asi01_preview["plan_id"],
        "submission_id": "e" * 32,
        "authorization_confirmed": True,
    })

    _, toolbot_dispatcher, toolbot_draft = _setup_managed_dispatcher(
        tmp_path / "toolbot",
        policy_ref="toolbot-offline-lab",
        target_id=LAB_ID,
        protocol="mcp-jsonrpc",
        endpoint=LAB_ENDPOINT,
        model=LAB_MODEL,
        capabilities=["tool_call"],
        transport_fn=lambda _: httpx.Response(403),
    )
    toolbot_workflow = ToolBotLabBatchWorkflow(toolbot_dispatcher)
    toolbot_sel = toolbot_workflow.selection_model.model_validate({
        "target": toolbot_draft,
        "testcase_ids": ["TM-002"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
    })
    toolbot_preview = toolbot_workflow.preview(toolbot_sel)
    toolbot_item = OfflineBatchStart.model_validate({
        "target": toolbot_draft,
        "testcase_ids": ["TM-002"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "expected_plan_id": toolbot_preview["plan_id"],
        "submission_id": "f" * 32,
        "authorization_confirmed": True,
    })

    monkeypatch.setattr(
        threading.Thread,
        "start",
        lambda _thread_self: (_ for _ in ()).throw(RuntimeError("thread allocation failed")),
    )

    with pytest.raises(RuntimeError, match="thread allocation failed"):
        asi01_workflow.start(asi01_item)
    assert asi01_dispatcher._active is False

    with pytest.raises(RuntimeError, match="thread allocation failed"):
        toolbot_workflow.start(toolbot_item)
    assert toolbot_dispatcher._active is False
    assert toolbot_workflow._active_grant_id is None
    assert toolbot_dispatcher.policy.grants == []


def test_normal_worker_contract_and_response_shape(tmp_path):
    offline_workflow, offline_dispatcher, draft = _setup_offline(tmp_path / "off")
    imp_client, headers, imported_workflow, imported_dispatcher, _, imported_draft, envelope = _setup_imported(tmp_path / "imp")

    off_item = _make_offline_start(offline_workflow, draft, submission_id="1" * 32)
    off_resp = offline_workflow.start(off_item)
    assert offline_workflow._worker is not None
    assert offline_workflow._worker.name == "secagent-offline-batch"
    assert offline_workflow._worker.daemon is False
    offline_workflow._worker.join(timeout=5)
    assert offline_dispatcher._active is False
    assert set(off_resp.keys()) == {
        "workflow_schema_version",
        "batch_run_id",
        "status",
        "plan_id",
        "progress_view",
    }
    assert off_resp["workflow_schema_version"] == "1.0.0"
    assert off_resp["progress_view"] == f"/api/testing/batches/{off_resp['batch_run_id']}"

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
    for kind in ("offline", "generic_imported"):
        if kind == "offline":
            workflow, dispatcher, draft = _setup_offline(tmp_path / kind)
            item = _make_offline_start(workflow, draft, submission_id="3" * 32)
            second_item = _make_offline_start(workflow, draft, submission_id="4" * 32)
        else:
            _, _, workflow, dispatcher, _, draft, envelope = _setup_imported(tmp_path / kind)
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

            # Fail-closed invariant: live worker MUST keep dispatcher._active == True until worker exits.
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
    off_wf, off_disp, off_draft = _setup_offline(tmp_path / "off_err")
    orig_off_run = off_wf.orchestrator.run
    call_count = 0

    def crash_first_run(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("synthetic orchestrator failure")
        return orig_off_run(*args, **kwargs)

    monkeypatch.setattr(off_wf.orchestrator, "run", crash_first_run)
    with pytest.raises(BatchRejected, match="Unknown or invalid batch run."):
        off_wf.start(_make_offline_start(off_wf, off_draft, submission_id="5" * 32))
    assert off_wf._worker is not None
    off_wf._worker.join(timeout=5)
    assert off_disp._active is False

    second_off = off_wf.start(_make_offline_start(off_wf, off_draft, submission_id="6" * 32))
    off_wf._worker.join(timeout=5)
    assert off_disp._active is False
    assert off_wf.orchestrator.state(second_off["batch_run_id"])["status"] == "completed"

    _, _, imp_wf, imp_disp, _, imp_draft, envelope = _setup_imported(tmp_path / "imp_err")
    monkeypatch.setattr(imp_wf.orchestrator, "run", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("imported crash")))
    with pytest.raises(BatchRejected, match="Unknown or invalid batch run."):
        imp_wf.start(_make_imported_start(imp_wf, imp_draft, envelope, submission_id="7" * 32))
    assert imp_wf._worker is not None
    imp_wf._worker.join(timeout=5)
    assert imp_disp._active is False
    assert imp_wf._active_grant_id is None
    assert imp_wf._owned_grants == set()


def test_cross_workflow_concurrency_guard_uses_worker_is_alive(tmp_path):
    worker_busy = threading.Event()
    release_worker = threading.Event()

    _, _, imported_wf, dispatcher, repo, imp_draft, envelope = _setup_imported(tmp_path)
    asi01_wf = Asi01BatchWorkflow(dispatcher)
    offline_wf = OfflineBatchWorkflow(dispatcher, [_make_offline_binding(0)], max_cases=5, max_total_requests=5)

    def gated_answer(_request):
        worker_busy.set()
        assert release_worker.wait(5)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "SecAgent is a prototype AI agent security testing system."}, "finish_reason": "stop"}]},
        )

    dispatcher.transport = httpx.MockTransport(gated_answer)

    app = create_app(
        dispatcher.catalog,
        dispatcher=dispatcher,
        operator_secret=SECRET,
        local_single_user=True,
        batch_services={"asi01": asi01_wf, "imported": imported_wf, "offline": offline_wf},
        dataset_repository=repo,
    )
    client = app.test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    headers = {
        "Origin": BASE,
        "X-SecAgent-Validation": health["validation_nonce"],
        "X-SecAgent-Operator": SECRET,
    }

    asi01_sel = {
        "target": imp_draft,
        "testcase_ids": ["GH-C01"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "workflow_id": "asi01",
    }
    p_asi01 = client.post("/api/testing/batches/preview", base_url=BASE, json=asi01_sel, headers=headers)
    assert p_asi01.status_code == 200
    s_asi01 = client.post(
        "/api/testing/batches",
        base_url=BASE,
        json=asi01_sel | {"expected_plan_id": p_asi01.json["plan_id"], "submission_id": "8" * 32, "authorization_confirmed": True},
        headers=headers,
    )
    assert s_asi01.status_code == 202
    assert worker_busy.wait(5)
    assert asi01_wf._worker is not None and asi01_wf._worker.is_alive()

    try:
        imp_sel = {
            "target": imp_draft,
            "dataset_id": envelope.dataset_id,
            "testcase_ids": [envelope.testcases[0].internal_id],
            "total_request_budget": 1,
            "evaluation_mode": "rule_only",
            "workflow_id": "imported",
        }
        p_imp = client.post("/api/testing/batches/preview", base_url=BASE, json=imp_sel, headers=headers)
        assert p_imp.status_code == 200
        s_imp = client.post(
            "/api/testing/batches",
            base_url=BASE,
            json=imp_sel | {"expected_plan_id": p_imp.json["plan_id"], "submission_id": "9" * 32, "authorization_confirmed": True},
            headers=headers,
        )
        assert s_imp.status_code == 409
        assert s_imp.json["error"]["code"] == "another_workflow_active"
    finally:
        release_worker.set()
        asi01_wf._worker.join(timeout=5)
