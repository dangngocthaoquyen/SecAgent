"""Tests for generic authorized direct-chat execution of imported testcase datasets."""

from hashlib import sha256
import json
from pathlib import Path
import socket
from time import sleep

import httpx
import pytest

from core.models import EvaluationStatus
from integrations.external_evaluator.models import ExternalEvaluationOutcome, ExternalEvaluationResult
from testing.evaluation_config import RunnerEvaluationConfig
from reporting.repository import _load_controlled_run, load_dataset
from reporting.api import create_app as reporting_app
from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig

BASE = "http://127.0.0.1:8092"
SECRET = "imported-batch-operator-" + "x" * 32
CODEBOT_JSON = Path(__file__).parent / "fixtures/datasets/codebot_asi02.synthetic.json"
REDTEAM_YAML = Path(__file__).parent / "fixtures/datasets/redteam_asi02.synthetic.yaml"


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def setup_imported_workflow(tmp_path, answer, *, review=True,
                            target_id="dvaa-researchbot", model="researchbot",
                            endpoint="http://127.0.0.1:7015/v1/chat/completions",
                            protocol="openai-chat", capabilities=("chat",),
                            hybrid_config=None, judge_provider=None):
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="imported-reviewed-lab", targets=[]), tmp_path / "operator-data",
        local_single_user=True)
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id=target_id, name="DVAA direct chat agent", platform_id="dvaa",
        platform_name="DVAA", endpoint=endpoint, protocol=protocol,
        model=model, timeout_seconds=3)))
    if review:
        row = catalog.review_profile(ReviewProfile(target_id=row["id"],
            profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
            endpoint=row["endpoint"], protocol=row["protocol"],
            model=row["default_model"], capabilities=list(capabilities),
            authorization_confirmed=True))
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint",
        "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(answer), output_boundary=output,
        hybrid_config=hybrid_config, judge_provider=judge_provider)
    repo = DatasetRepository(tmp_path / "operator-data")
    envelope = normalize_dataset(CODEBOT_JSON.read_bytes(), "testcases_dvaa_codebot_asi02.json")
    repo.save_dataset(envelope)
    workflow = GenericImportedBatchWorkflow(dispatcher, repo)
    app = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_service=workflow, dataset_repository=repo)
    client = app.test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": SECRET}
    return client, headers, workflow, dispatcher, repo, draft, envelope, health


def post(client, route, body, headers):
    if route in {"batches", "batches/preview"} and body.get("dataset_id"):
        ds = client.get("/api/testing/datasets/" + body["dataset_id"], base_url=BASE, headers=headers).json.get("dataset")
        if ds:
            mapping = {c["testcase_id"]: c["internal_id"] for c in ds["testcases"]}
            body = body | {"testcase_ids": [mapping.get(i, i) for i in body["testcase_ids"]]}
    return client.post("/api/testing/" + route, base_url=BASE, json=body, headers=headers)


def get(client, route, headers):
    return client.get("/api/testing/" + route, base_url=BASE, headers=headers)


def terminal(client, identity, headers):
    for _ in range(160):
        response = get(client, f"batches/{identity}", headers)
        assert response.status_code == 200, response.json
        row = response.json
        if row["status"] in {"completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            return row
        sleep(0.05)
    pytest.fail("Batch did not terminate")


def test_unified_registry_routes_explicit_workflow_without_target_request(tmp_path):
    client, _, imported, dispatcher, repo, draft, envelope, _ = setup_imported_workflow(
        tmp_path, lambda _: (_ for _ in ()).throw(AssertionError('No target request expected')))
    app = create_app(dispatcher.catalog, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_services={'imported': imported}, dataset_repository=repo)
    client = app.test_client()
    health = client.get('/api/testing/health', base_url=BASE).json
    assert health['asi01_batch_enabled'] is False and health['custom_imported_batch_enabled'] is True
    assert health['registered_workflows'] == ['imported']
    headers = {'Origin': BASE, 'X-SecAgent-Validation': health['validation_nonce'], 'X-SecAgent-Operator': SECRET}
    selection = {'target': draft, 'testcase_ids': ['TC0001'],
        'total_request_budget': 1, 'evaluation_mode': 'rule_only', 'dataset_id': envelope.dataset_id}
    bad_wf = post(client, 'batches/preview', selection | {'workflow_id': 'asi01'}, headers)
    assert bad_wf.status_code == 400 and bad_wf.json['error']['code'] == 'workflow_selection_required'
    imported_preview = post(client, 'batches/preview', selection | {'workflow_id': 'imported'}, headers)
    assert imported_preview.status_code == 200 and imported_preview.json['execution_mode'] == 'custom_imported'


def test_single_imported_case_executes_and_generates_report(tmp_path):
    received_requests = []
    def answer(request):
        received_requests.append(request)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "I cannot perform that sensitive action."}, "finish_reason": "stop"}]
        })

    client, headers, workflow, dispatcher, repo, draft, envelope, health = setup_imported_workflow(tmp_path, answer)
    assert health["custom_imported_batch_enabled"] is True
    assert health["target_network_access"] is False

    selection = {
        "target": draft,
        "testcase_ids": ["TC0001"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    pdata = preview.json
    assert pdata["total"] == 1
    assert pdata["ready_count"] == 1
    assert pdata["items"][0]["status"] == "ready"
    assert pdata["execution_mode"] == "custom_imported"

    started = post(client, "batches", selection | {
        "expected_plan_id": pdata["plan_id"],
        "submission_id": "1" * 32,
        "authorization_confirmed": True,
    }, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]

    status = terminal(client, identity, headers)
    workflow._worker.join(5)
    assert status["status"] == "completed"
    assert status["processed"] == 1
    assert len(received_requests) == 1

    # Verify request payload preserves exact prompt
    body = json.loads(received_requests[0].content)
    assert body["messages"][0]["content"] == envelope.testcases[0].prompt

    results = get(client, f"batches/{identity}/results", headers).json["results"]
    assert len(results) == 1
    assert results[0]["testcase_id"] == envelope.testcases[0].internal_id
    assert results[0]["status"] == "completed"
    assert results[0]["verdict"] == "INCONCLUSIVE"
    assert results[0]["report_run_id"] is not None

    # Verify report is accessible via reporting dataset
    report_file = dispatcher.output_root / results[0]["report_run_id"] / f"native-{envelope.testcases[0].internal_id}-{results[0]['report_run_id']}.secagent.json"
    assert report_file.exists()
    report_json = json.loads(report_file.read_text(encoding="utf-8"))
    assert report_json["source_testcase_id"] == "TC0001"
    assert report_json["dataset_id"] == envelope.dataset_id
    assert report_json["prompt_sha256"] == envelope.testcases[0].prompt_sha256


def test_two_imported_cases_execute_sequentially(tmp_path):
    received = []
    def answer(request):
        received.append(request)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Understood."}, "finish_reason": "stop"}]
        })

    client, headers, workflow, dispatcher, repo, draft, envelope, _ = setup_imported_workflow(tmp_path, answer)
    selection = {
        "target": draft,
        "testcase_ids": ["TC0001", "TC0002"],
        "total_request_budget": 2,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    pdata = post(client, "batches/preview", selection, headers).json
    assert pdata["ready_count"] == 2

    started = post(client, "batches", selection | {
        "expected_plan_id": pdata["plan_id"],
        "submission_id": "2" * 32,
        "authorization_confirmed": True,
    }, headers)
    identity = started.json["batch_run_id"]
    status = terminal(client, identity, headers)
    workflow._worker.join(5)

    assert status["status"] == "completed"
    assert status["processed"] == 2
    assert len(received) == 2
    assert json.loads(received[0].content)["messages"][0]["content"] == envelope.testcases[0].prompt
    assert json.loads(received[1].content)["messages"][0]["content"] == envelope.testcases[1].prompt


def test_thirty_testcase_batch_executes_without_grant_capacity_exhaustion(tmp_path):
    received = []
    def answer(request):
        received.append(request)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Generic target response."}, "finish_reason": "stop"}]
        })

    client, headers, workflow, dispatcher, repo, draft, envelope, _ = setup_imported_workflow(tmp_path, answer)

    all_case_ids = [c.testcase_id for c in envelope.testcases]
    assert len(all_case_ids) == 30

    selection = {
        "target": draft,
        "testcase_ids": all_case_ids,
        "total_request_budget": 30,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    pdata = preview.json
    assert pdata["total"] == 30
    assert pdata["ready_count"] == 30
    assert all(item["status"] == "ready" for item in pdata["items"])

    started = post(client, "batches", selection | {
        "expected_plan_id": pdata["plan_id"],
        "submission_id": "3" * 32,
        "authorization_confirmed": True,
    }, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]

    status = terminal(client, identity, headers)
    workflow._worker.join(10)

    assert status["status"] == "completed"
    assert status["processed"] == 30
    assert status["target_request_count"] == 30
    assert status["request_budget_consumed"] == 30
    assert len(received) == 30

    # Policy grant list must remain bounded (0 or 1 at all times; 0 at completion)
    assert len(dispatcher.policy.grants) == 0

    # Exactly 30 grants created and consumed on disk
    grant_files = list(workflow.root.glob("grant-*"))
    assert len(grant_files) == 30

    # Every request matches original imported prompt
    for idx, req in enumerate(received):
        sent_body = json.loads(req.content)
        assert sent_body["messages"][0]["content"] == envelope.testcases[idx].prompt

    results = get(client, f"batches/{identity}/results", headers).json["results"]
    assert len(results) == 30
    for r in results:
        assert r["status"] == "completed"
        assert r["verdict"] == "INCONCLUSIVE"
        assert r["report_run_id"] is not None
        assert r["report_sha256"] is not None


def test_unreviewed_or_incompatible_target_blocks_batch(tmp_path):
    client, headers, workflow, _, _, draft, envelope, _ = setup_imported_workflow(
        tmp_path, lambda req: httpx.Response(200), review=False)

    selection = {
        "target": draft,
        "testcase_ids": ["TC0001"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    pdata = preview.json
    assert pdata["ready_count"] == 0
    assert pdata["items"][0]["status"] == "blocked"
    assert pdata["items"][0]["reason"] == "imported_target_not_reviewed"


def test_replaying_consumed_grant_is_rejected(tmp_path):
    def answer(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})

    client, headers, workflow, dispatcher, repo, draft, envelope, _ = setup_imported_workflow(tmp_path, answer)
    selection = {
        "target": draft,
        "testcase_ids": ["TC0001"],
        "total_request_budget": 1,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {
        "expected_plan_id": preview["plan_id"],
        "submission_id": "4" * 32,
        "authorization_confirmed": True,
    }, headers)
    identity = started.json["batch_run_id"]
    terminal(client, identity, headers)
    workflow._worker.join(5)

    grant_file = list(workflow.root.glob("grant-*"))[0]
    auth_id = grant_file.name.replace("grant-", "")
    from workflow.generic_imported_batch import ImportedBatchSelection
    sel = ImportedBatchSelection.model_validate(selection)
    assert workflow._grant(sel, "TC0001", preview["items"][0]["asset_sha256"]) is None


def test_batch_cancellation_preserves_partial_results(tmp_path):
    def answer(request):
        sleep(0.1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})

    client, headers, workflow, dispatcher, repo, draft, envelope, _ = setup_imported_workflow(tmp_path, answer)
    selection = {
        "target": draft,
        "testcase_ids": ["TC0001", "TC0002", "TC0003"],
        "total_request_budget": 3,
        "evaluation_mode": "rule_only",
        "dataset_id": envelope.dataset_id,
    }
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {
        "expected_plan_id": preview["plan_id"],
        "submission_id": "5" * 32,
        "authorization_confirmed": True,
    }, headers)
    identity = started.json["batch_run_id"]

    post(client, f"batches/{identity}/cancel", {}, headers)
    status = terminal(client, identity, headers)
    workflow._worker.join(5)

    assert status["status"] in {"cancelled", "partially_completed", "completed"}
    results = get(client, f"batches/{identity}/results", headers).json["results"]
    assert len(results) == 3
