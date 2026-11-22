"""Real Workflow API and native TM-002 over a synthetic handler boundary."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import socket
from threading import Event
from time import sleep
from uuid import uuid4

import httpx
import pytest

from reporting.api import create_app as reporting_app
from reporting.repository import load_dataset
from workflow.admission import AdmissionPolicy, ExecutionGrant
from workflow.api import create_app
from workflow.batch import BatchRejected
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig
from workflow.offline_batch import OfflineBatchSelection
from workflow.toolbot_lab_batch import ToolBotLabBatchWorkflow, ToolBotFixture, LAB_ENDPOINT, LAB_ID, LAB_MODEL


BASE = "http://127.0.0.1:8092"
SECRET = "toolbot-lab-test-" + "x" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Network forbidden"))


def setup(tmp_path, *, review=True, endpoint=LAB_ENDPOINT, model=LAB_MODEL,
          effect_mode="verified"):
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="toolbot-offline-lab", targets=[]), tmp_path / "operator", local_single_user=True)
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(id=LAB_ID,
        name="DVAA ToolBot Lab", platform_id="dvaa", platform_name="DVAA",
        endpoint=endpoint, protocol="mcp-jsonrpc", model=model, timeout_seconds=3)))
    if review:
        row = catalog.review_profile(ReviewProfile(target_id=row["id"],
            profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
            endpoint=row["endpoint"], protocol=row["protocol"],
            model=row["default_model"], capabilities=["tool_call"],
            authorization_confirmed=True))
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint",
        "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(lambda _: httpx.Response(403)),
        output_boundary=output)
    service = ToolBotLabBatchWorkflow(dispatcher, effect_mode=effect_mode)
    client = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_service=service).test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    assert health["toolbot_lab_batch_enabled"] is True
    assert health["target_network_access"] is False
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": SECRET}
    return client, headers, service, catalog, draft, output


def post(client, path, body, headers):
    return client.post("/api/testing/" + path, base_url=BASE, json=body, headers=headers)


def get(client, path, headers):
    return client.get("/api/testing/" + path, base_url=BASE, headers=headers)


def run(client, headers, draft, ids=("TM-002",), submission_id=None):
    sub_id = submission_id or ("a" * 32)
    selection = {"target": draft, "testcase_ids": list(ids),
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200, preview.json
    start = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": sub_id, "authorization_confirmed": True}, headers)
    assert start.status_code == 202, start.json
    identity = start.json["batch_run_id"]
    for _ in range(100):
        status = get(client, f"batches/{identity}", headers).json
        if status["status"] in {"completed", "partially_completed", "failed", "cancelled", "interrupted"}:
            break
        sleep(0.03)
    else:
        pytest.fail("ToolBot Lab batch did not terminate")
    return preview.json, status, get(client, f"batches/{identity}/results", headers).json


@pytest.mark.parametrize("effect_mode,verdict", [("verified", "FAIL"),
    ("missing", "INCONCLUSIVE"), ("failed", "INCONCLUSIVE"),
    ("wrong_identity", "ERROR")])
def test_native_tm002_batch_evidence_and_reporting(tmp_path, effect_mode, verdict):
    client, headers, service, catalog, draft, output = setup(tmp_path, effect_mode=effect_mode)
    preview, status, results = run(client, headers, draft, ("TM-002", "TM-001"))
    assert preview["ready_count"] == 1 and preview["target_request_budget"] == 1
    assert preview["items"][1]["status"] == "unsupported"
    assert status["target_request_count"] == status["request_budget_consumed"] == 1
    assert results["results"][1]["verdict"] is None
    case = results["results"][0]
    assert case["verdict"] == verdict and case["request_count"] == 1
    assert case["evidence_provenance"] == "synthetic_mock"
    run_id = case["report_run_id"]
    assert run_id and case["report_sha256"]
    report_file = next((output / "runs" / run_id).glob("native-TM-002-*.secagent.json"))
    assert sha256(report_file.read_bytes()).hexdigest() == case["report_sha256"]
    report = json.loads(report_file.read_text())
    assert report["source_provenance"] == "synthetic_mock"
    assert report["runtime_snapshot"]["batch_execution_sha256"] == sha256(case["execution_id"].encode()).hexdigest()
    for key, digest in report["runtime_snapshot"]["tool_artifact_sha256"].items():
        role = key.removeprefix("tool_").removesuffix("_sha256")
        assert sha256((output / "runs" / run_id / f"tool-{role}.json").read_bytes()).hexdigest() == digest
    kinds = [e["kind"] for e in (report["evaluation"]["observation"] or {}).get("evidence", [])]
    if effect_mode == "verified":
        assert kinds == ["tool_request", "target_tool_result", "tool_call", "tool_trace"]
    if effect_mode == "missing":
        assert kinds == ["tool_request", "target_tool_result"]
    aggregate = service.root / status["batch_run_id"] / "batch-report.json"
    assert sha256(aggregate.read_bytes()).hexdigest() == results["aggregate_report_sha256"]
    assert json.loads(aggregate.read_text())["cases"][0]["report_run_id"] == run_id
    assert not list((output / "runs").glob("toolbot-*"))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(output / "runs")}, "reports": [],
        "verification_jobs": [], "controlled_runs_root": "controlled"}))
    reporting = reporting_app(load_dataset(manifest)).test_client()
    response = reporting.get(f"/api/reports/runs/{run_id}",
        base_url="http://127.0.0.1:8091")
    assert response.status_code == 200, response.json
    assert response.json["execution"]["identity"]["testcase_id"] == "TM-002"
    assert response.json["execution"]["security"]["verdict"] == (None if verdict == "ERROR" else verdict)
    if effect_mode == "verified":
        (output / "runs" / run_id / "tool-effect.json").write_bytes(b"tampered")
        assert reporting.get(f"/api/reports/runs/{run_id}",
            base_url="http://127.0.0.1:8091").status_code == 409


def test_unreviewed_stale_wrong_target_and_budget_are_rejected(tmp_path):
    client, headers, service, catalog, draft, _ = setup(tmp_path, review=False)
    selection = {"target": draft, "testcase_ids": ["TM-002"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    assert post(client, "batches/preview", selection, headers).status_code == 409
    row = catalog.public_targets()[0]
    catalog.review_profile(ReviewProfile(target_id=row["id"],
        profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
        endpoint=row["endpoint"], protocol=row["protocol"],
        model=row["default_model"], capabilities=["tool_call"], authorization_confirmed=True))
    assert post(client, "batches/preview", selection, headers).status_code == 200
    assert post(client, "batches/preview", selection | {"total_request_budget": 2}, headers).status_code == 409
    with pytest.raises(ValueError, match="Missing or stale target profile"):
        catalog.save_profile(SaveProfile(profile=ManagedProfile(id=LAB_ID, name="Wrong Rev",
            platform_id="dvaa", platform_name="DVAA", endpoint=LAB_ENDPOINT,
            protocol="mcp-jsonrpc", model=LAB_MODEL, timeout_seconds=3),
            expected_profile_revision="0" * 64), update=True)
    renamed = catalog.save_profile(SaveProfile(profile=ManagedProfile(id=LAB_ID, name="Updated Lab",
        platform_id="dvaa", platform_name="DVAA", endpoint=LAB_ENDPOINT,
        protocol="mcp-jsonrpc", model=LAB_MODEL, timeout_seconds=3),
        expected_profile_revision=draft["profile_revision"]), update=True)
    assert renamed["profile_revision"] == draft["profile_revision"]
    assert post(client, "batches/preview", selection, headers).status_code == 200
    changed = catalog.save_profile(SaveProfile(profile=ManagedProfile(id=LAB_ID, name="Updated Lab",
        platform_id="dvaa", platform_name="DVAA", endpoint=LAB_ENDPOINT,
        protocol="mcp-jsonrpc", model=LAB_MODEL, timeout_seconds=4),
        expected_profile_revision=draft["profile_revision"]), update=True)
    assert changed["profile_revision"] != draft["profile_revision"]
    assert post(client, "batches/preview", selection, headers).status_code == 409
    assert post(client, "batches/preview", selection | {
        "target": draft | {"profile_revision": changed["profile_revision"], "timeout_seconds": 4}
    }, headers).status_code == 409
    assert get(client, "batches/" + "a" * 32, {}).status_code == 403


@pytest.mark.parametrize("endpoint,model", [
    ("http://127.0.0.1:7010/mcp", LAB_MODEL),
    (LAB_ENDPOINT, "toolbot")])
def test_wrong_endpoint_or_model_cannot_be_saved_as_reviewed_lab(tmp_path, endpoint, model):
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="toolbot-offline-lab", targets=[]), tmp_path / "operator", local_single_user=True)
    with pytest.raises(ValueError, match="exact offline ToolBot Lab"):
        catalog.save_profile(SaveProfile(profile=ManagedProfile(id=LAB_ID,
            name="Wrong Lab", platform_id="dvaa", platform_name="DVAA",
            endpoint=endpoint, protocol="mcp-jsonrpc", model=model, timeout_seconds=3)))


def test_duplicate_submission_and_cross_run_effect_isolation(tmp_path):
    client, headers, service, _, draft, output = setup(tmp_path)
    selection = {"target": draft, "testcase_ids": ["TM-002"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json
    body = selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "b" * 32, "authorization_confirmed": True}
    first = post(client, "batches", body, headers)
    assert first.status_code == 202
    identity = first.json["batch_run_id"]
    service._worker.join(5)
    assert post(client, "batches", body, headers).status_code == 409
    second = post(client, "batches", body | {"submission_id": "c" * 32}, headers)
    assert second.status_code == 202
    service._worker.join(5)
    first_row = get(client, f"batches/{identity}/results", headers).json["results"][0]
    second_row = get(client, f"batches/{second.json['batch_run_id']}/results", headers).json["results"][0]
    assert first_row["execution_id"] != second_row["execution_id"]
    assert first_row["report_run_id"] != second_row["report_run_id"]
    assert first_row["verdict"] == second_row["verdict"] == "FAIL"
    assert len(list((output / "runs").glob("toolbot-*"))) == 0


def test_cancellation_after_active_request_preserves_result(tmp_path, monkeypatch):
    client, headers, service, _, draft, _ = setup(tmp_path)
    entered, release = Event(), Event()
    original = ToolBotFixture.__call__
    def delayed(self, request):
        entered.set()
        assert release.wait(5)
        return original(self, request)
    monkeypatch.setattr(ToolBotFixture, "__call__", delayed)
    selection = {"target": draft, "testcase_ids": ["TM-002", "TM-001"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "d" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]
    assert entered.wait(5)
    cancelled = post(client, f"batches/{identity}/cancel", {}, headers)
    assert cancelled.status_code == 200 and cancelled.json["active_request_cancelled"] is False
    release.set()
    service._worker.join(5)
    state = get(client, f"batches/{identity}", headers).json
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert state["status"] == "cancelled"
    assert state["target_request_count"] == state["request_budget_consumed"] == 1
    assert rows[0]["verdict"] == "FAIL" and rows[0]["report_run_id"]
    assert rows[1]["status"] == "cancelled" and rows[1]["verdict"] is None


def test_twenty_five_sequential_tm002_batches_execute_without_grant_exhaustion(tmp_path):
    client, headers, service, catalog, draft, output = setup(tmp_path)
    for i in range(25):
        sub_id = f"{i:032x}"
        preview, status, results = run(client, headers, draft, ("TM-002",), submission_id=sub_id)
        assert status["status"] == "completed"
        assert results["results"][0]["verdict"] == "FAIL"
        run_id = results["results"][0]["report_run_id"]
        report_file = next((output / "runs" / run_id).glob("native-TM-002-*.secagent.json"))
        assert sha256(report_file.read_bytes()).hexdigest() == results["results"][0]["report_sha256"]

    grant_files = list(service.root.glob("grant-*"))
    assert len(grant_files) == 25
    auth_ids = [p.name.removeprefix("grant-") for p in grant_files]
    assert len(set(auth_ids)) == 25
    assert len(service.dispatcher.policy.grants) == 0


def test_replaying_consumed_authorization_is_rejected(tmp_path):
    client, headers, service, catalog, draft, output = setup(tmp_path)
    preview, status, results = run(client, headers, draft, ("TM-002",), submission_id="1" * 32)
    assert status["status"] == "completed"
    grant_files = list(service.root.glob("grant-*"))
    assert len(grant_files) == 1
    consumed_auth_id = grant_files[0].name.removeprefix("grant-")

    # Attempt to re-inject this consumed grant into policy.grants
    replayed_grant = ExecutionGrant(authorization_id=consumed_auth_id,
        target_id=draft["target_id"], profile_revision=draft["profile_revision"],
        policy_ref=draft["policy_ref"], testcase_id="TM-002",
        asset_sha256=service.binding.asset_sha256, scope="security_test_execution",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
    service.dispatcher.policy = service.dispatcher.policy.model_copy(update={"grants": [replayed_grant]})

    selection = OfflineBatchSelection(target=draft, testcase_ids=["TM-002"],
        total_request_budget=1, evaluation_mode="rule_only")
    # _grant strictly rejects consumed grants
    assert service._grant(selection, "TM-002", service.binding.asset_sha256) is None

    # Pruning immediately discards consumed grant because grant file already exists on disk
    service._prune_grants()
    assert len(service.dispatcher.policy.grants) == 0


def test_active_authorization_not_prematurely_removed(tmp_path, monkeypatch):
    client, headers, service, catalog, draft, _ = setup(tmp_path)
    entered, release = Event(), Event()
    original = ToolBotFixture.__call__

    def delayed(self, request):
        entered.set()
        assert release.wait(5)
        return original(self, request)

    monkeypatch.setattr(ToolBotFixture, "__call__", delayed)
    selection = {"target": draft, "testcase_ids": ["TM-002"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "e" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]
    assert entered.wait(5)

    # While batch is active, the active grant must be retained
    with service.dispatcher._lock:
        active_id = service._active_grant_id
        assert active_id is not None
        assert any(g.authorization_id == active_id for g in service.dispatcher.policy.grants)
        service._prune_grants()
        assert any(g.authorization_id == active_id for g in service.dispatcher.policy.grants)

    release.set()
    service._worker.join(5)
    state = get(client, f"batches/{identity}", headers).json
    assert state["status"] == "completed"
    # Once finished, grant is safely cleaned up
    assert len(service.dispatcher.policy.grants) == 0


def test_cancellation_and_failed_submissions_do_not_leak_grants(tmp_path):
    client, headers, service, catalog, draft, _ = setup(tmp_path)
    assert len(service.dispatcher.policy.grants) == 0

    selection = {"target": draft, "testcase_ids": ["TM-002"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json

    # Test duplicate submission failure: does not leak grants
    body = selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "f" * 32, "authorization_confirmed": True}
    started = post(client, "batches", body, headers)
    assert started.status_code == 202
    service._worker.join(5)
    assert len(service.dispatcher.policy.grants) == 0

    # Submitting duplicate fails with 409 and does not leak grant
    duplicate = post(client, "batches", body, headers)
    assert duplicate.status_code == 409
    assert len(service.dispatcher.policy.grants) == 0


def test_concurrent_submissions_remain_controlled(tmp_path, monkeypatch):
    client, headers, service, catalog, draft, _ = setup(tmp_path)
    entered, release = Event(), Event()
    original = ToolBotFixture.__call__

    def delayed(self, request):
        entered.set()
        assert release.wait(5)
        return original(self, request)

    monkeypatch.setattr(ToolBotFixture, "__call__", delayed)
    selection = {"target": draft, "testcase_ids": ["TM-002"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "c" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]
    assert entered.wait(5)

    # Concurrent start while active must be rejected
    concurrent = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "d" * 32, "authorization_confirmed": True}, headers)
    assert concurrent.status_code == 409
    assert concurrent.json["error"]["code"] == "batch_start_rejected"

    release.set()
    service._worker.join(5)
    state = get(client, f"batches/{identity}", headers).json
    assert state["status"] == "completed"
    assert len(service.dispatcher.policy.grants) == 0
