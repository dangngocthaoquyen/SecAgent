"""Offline checks for the generic, explicitly selected Live Local imported path."""

import json
import socket
from datetime import timedelta
from time import sleep

import httpx
import pytest

from reporting.normalizers import normalize_report_bytes
from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dataset_normalizer import normalize_dataset
from workflow.dataset_repository import DatasetRepository
from workflow.dispatch import ControlledDispatcher
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.asi01_batch import load_text_binding
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "generic-local-test-" + "x" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Network access forbidden"))


def setup(tmp_path, monkeypatch, *, endpoint="http://127.0.0.1:7345/v1/chat/completions",
          model="another-agent", target_id="operator-agent", reviewed=True, answer_override=None):
    requests = []

    # Only the external HTTP boundary is replaced. Workflow, adapter, Runner,
    # evaluator, persistence and API remain real. No socket can connect.
    def recorded_answer(request):
        requests.append(request)
        return answer_override(request) if answer_override else httpx.Response(200, json={
            "choices": [{"message": {"content": "ready"}, "finish_reason": "stop"}]})
    transport = httpx.MockTransport(recorded_answer)
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="generic-local-policy", targets=[]), tmp_path / "operator", local_single_user=True)
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(id=target_id,
        name="Operator Agent", platform_id="local", platform_name="Local",
        endpoint=endpoint, protocol="openai-chat", model=model, timeout_seconds=3)))
    if reviewed:
        row = catalog.review_profile(ReviewProfile(target_id=row["id"],
            profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
            endpoint=row["endpoint"], protocol=row["protocol"], model=row["default_model"],
            capabilities=["chat"], authorization_confirmed=True))
    repo = DatasetRepository(tmp_path / "operator")
    dataset = normalize_dataset(json.dumps({"testcases": [
        {"id": "one", "prompt": "Summarize a public project description."},
        {"id": "two", "prompt": "Explain a benign example."},
    ]}).encode(), "local.json")
    repo.save_dataset(dataset)
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), tmp_path / "results" / "runs",
        operator_secret=SECRET, output_boundary=tmp_path / "results")
    workflow = GenericImportedBatchWorkflow(dispatcher, repo, execution_mode="both",
        mock_live_transport=transport)
    client = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_service=workflow, dataset_repository=repo).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Operator": SECRET, "X-SecAgent-Validation": nonce}
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint", "protocol",
        "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=model, timeout_seconds=3)
    selection = {"target": draft, "testcase_ids": [dataset.testcases[0].internal_id],
        "total_request_budget": 1, "evaluation_mode": "rule_only", "dataset_id": dataset.dataset_id,
        "transport_mode": "live_local_http"}
    return client, headers, workflow, catalog, row, dataset, requests, selection


def post(client, path, body, headers):
    return client.post("/api/testing/" + path, base_url=BASE, json=body, headers=headers)


def test_reviewed_generic_agent_probe_and_live_local_batch(tmp_path, monkeypatch):
    client, headers, workflow, catalog, row, dataset, requests, selection = setup(tmp_path, monkeypatch)
    blocked = post(client, "batches/preview", selection, headers)
    assert blocked.status_code == 200
    assert blocked.json["items"][0]["reason"] == "imported_live_connection_check_required"
    probe = post(client, "connection-checks", {"target_id": row["id"],
        "profile_revision": row["profile_revision"], "policy_ref": row["policy_ref"]}, headers)
    assert probe.status_code == 200 and probe.json["runtime_protocol_compatible"] is True
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200 and preview.json["ready_count"] == 1
    assert preview.json["transport_mode"] == "live_local_http"
    assert preview.json["target_request_budget"] == 1
    start = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "a" * 32, "authorization_confirmed": True}, headers)
    assert start.status_code == 202, start.json
    identity = start.json["batch_run_id"]
    for _ in range(100):
        status = client.get(f"/api/testing/batches/{identity}", base_url=BASE, headers=headers).json
        if status["status"] in {"completed", "failed", "partially_completed"}:
            break
        sleep(.05)
    workflow._worker.join(5)
    assert status["status"] == "completed"
    assert status["target_request_count"] == 1
    assert len(requests) == 2  # One benign probe, one selected testcase.
    assert requests[1].url.path == "/v1/chat/completions"
    assert json.loads(requests[1].content)["messages"][0]["content"] == dataset.testcases[0].prompt
    results = client.get(f"/api/testing/batches/{identity}/results", base_url=BASE, headers=headers).json
    case = results["results"][0]
    assert case["verdict"] == "INCONCLUSIVE" and case["evidence_provenance"] == "synthetic_mock"
    report = next((workflow.dispatcher.output_root / case["report_run_id"]).glob("native-*.secagent.json"))
    native = json.loads(report.read_text(encoding="utf-8"))
    assert native["runtime_snapshot"]["transport_mode"] == "live_local_http"
    assert native["source_provenance"] == "synthetic_mock"
    assert normalize_report_bytes(report.read_bytes()).imported_provenance.evidence_provenance == "synthetic_mock"
    assert native["imported_provenance"]["target_profile_id"] == "operator-agent"
    assert native["imported_provenance"]["connection_probe_id"]


def test_live_local_rejects_unreviewed_and_wrong_destination(tmp_path, monkeypatch):
    client, headers, _, _, row, _, requests, selection = setup(tmp_path, monkeypatch, reviewed=False)
    response = post(client, "batches/preview", selection, headers)
    assert response.json["items"][0]["reason"] == "imported_target_not_reviewed"
    assert requests == []
    client, headers, _, _, row, _, requests, selection = setup(tmp_path / "other", monkeypatch,
        endpoint="http://127.0.0.1:7345/other")
    response = post(client, "batches/preview", selection, headers)
    assert response.json["items"][0]["reason"] == "imported_live_loopback_endpoint_required"
    assert requests == []


def test_offline_choice_remains_mock_without_probe(tmp_path, monkeypatch):
    client, headers, workflow, _, _, _, requests, selection = setup(tmp_path, monkeypatch)
    selection["transport_mode"] = "offline_mock"
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200 and preview.json["ready_count"] == 1
    started = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "b" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    workflow._worker.join(5)
    identity = started.json["batch_run_id"]
    results = client.get(f"/api/testing/batches/{identity}/results", base_url=BASE, headers=headers).json
    assert results["results"][0]["evidence_provenance"] == "synthetic_mock"
    assert requests == []
    run_id = results["results"][0]["report_run_id"]
    report = next((workflow.dispatcher.output_root / run_id).glob("native-*.secagent.json"))
    assert normalize_report_bytes(report.read_bytes()).imported_provenance.execution_mode == "offline_mock"


def test_agent_bridge_report_preserves_partial_reported_tool_trace(tmp_path, monkeypatch):
    def answer(_request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Synthetic assistant answer"},
                         "finish_reason": "stop"}],
            "secagent_bridge": {"schema_version": "1.0.0",
                "provenance": "provider_reported", "execution_verified": False,
                "trace_completeness": "partial", "tool_calls": [{
                    "index": 0, "tool_name": "read_file", "arguments_sha256": "a" * 64,
                    "invoked": True, "mcp_response_present": True}]}})
    client, headers, workflow, _, target, _, requests, selection = setup(
        tmp_path, monkeypatch, endpoint="http://127.0.0.1:7019/v1/chat/completions",
        model="deepseek-chat", target_id="toolbot-agent-bridge", answer_override=answer)
    post(client, "connection-checks", {"target_id": target["id"],
        "profile_revision": target["profile_revision"], "policy_ref": target["policy_ref"]}, headers)
    preview = post(client, "batches/preview", selection, headers).json
    assert preview["ready_count"] == 1 and preview["target_request_budget"] == 1
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "c" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    workflow._worker.join(5)
    results = client.get(f"/api/testing/batches/{started.json['batch_run_id']}/results",
        base_url=BASE, headers=headers).json["results"]
    assert len(requests) == 2 and len(results) == 1
    assert results[0]["verdict"] == "INCONCLUSIVE"
    report = next((workflow.dispatcher.output_root / results[0]["report_run_id"]).glob("native-*.secagent.json"))
    native = json.loads(report.read_text(encoding="utf-8"))
    events = native["evaluation"]["observation"]["evidence"]
    call = next(event for event in events if event["kind"] == "agent_bridge_tool_call")
    assert call["data"]["provenance"] == "target_reported"
    assert call["data"]["execution_verified"] is False
    assert call["data"]["trace_completeness"] == "partial"
    assert native["imported_provenance"]["target_profile_id"] == "toolbot-agent-bridge"


def test_reviewed_web_lab_profile_can_probe_and_proof_expires_or_becomes_stale(tmp_path, monkeypatch):
    client, headers, workflow, catalog, row, _, requests, selection = setup(tmp_path, monkeypatch,
        endpoint="http://127.0.0.1:17016/v1/chat/completions", model="researchbot",
        target_id="dvaa-researchbot-web-lab")
    public = next(p for p in catalog.public_targets() if p["id"] == row["id"])
    assert public["connection_probe"]["status"] == "supported"
    assert client.get("/api/testing/targets", base_url=BASE).json["targets"][0]["connection_verification"]["status"] == "not_checked"
    assert post(client, "batches/preview", selection, headers).json["items"][0]["reason"] == (
        "imported_live_connection_check_required")
    probe = post(client, "connection-checks", {"target_id": row["id"],
        "profile_revision": row["profile_revision"], "policy_ref": row["policy_ref"]}, headers)
    assert probe.status_code == 200 and probe.json["connection_status"] == "succeeded"
    assert client.get("/api/testing/targets", base_url=BASE).json["targets"][0]["connection_verification"]["status"] == "compatible"
    assert post(client, "batches/preview", selection, headers).json["ready_count"] == 1
    proof = workflow._connection_proofs[row["id"]]
    proof["verified_at"] -= timedelta(minutes=11)
    assert post(client, "batches/preview", selection, headers).json["items"][0]["reason"] == (
        "imported_live_connection_check_expired")
    assert client.get("/api/testing/targets", base_url=BASE).json["targets"][0]["connection_verification"]["status"] == "expired"
    proof["verified_at"] += timedelta(minutes=11)
    proof["model"] = "old-model"
    assert post(client, "batches/preview", selection, headers).json["items"][0]["reason"] == (
        "imported_live_connection_check_stale")
    assert client.get("/api/testing/targets", base_url=BASE).json["targets"][0]["connection_verification"]["status"] == "stale"
    assert len(requests) == 1  # Only the operator-triggered benign mock probe.


def test_exact_pinned_asi01_inputs_use_native_rules_and_same_batch_baseline(tmp_path, monkeypatch):
    control = load_text_binding("GH-C01")
    attack = load_text_binding("GH-001")

    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        content = ("ready" if prompt == "Reply with one word: ready." else
                   "SecAgent is a prototype AI agent security testing system." if prompt == control.test_input.prompt else
                   "SECAGENT_GH_HIJACKED" if prompt == attack.test_input.prompt else "unknown")
        return httpx.Response(200, json={"choices": [{"message": {"content": content},
                                                      "finish_reason": "stop"}]})

    client, headers, workflow, _, target, _, requests, selection = setup(
        tmp_path, monkeypatch, answer_override=answer)
    ds = normalize_dataset(json.dumps({"testcases": [
        {"id": "control", "prompt": control.test_input.prompt},
        {"id": "attack", "prompt": attack.test_input.prompt},
    ]}).encode(), "pinned-native-inputs.json")
    workflow.dataset_repository.save_dataset(ds)
    selection.update(dataset_id=ds.dataset_id,
        testcase_ids=[case.internal_id for case in ds.testcases], total_request_budget=2)
    probe = post(client, "connection-checks", {"target_id": target["id"],
        "profile_revision": target["profile_revision"], "policy_ref": target["policy_ref"]}, headers)
    assert probe.status_code == 200
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200 and preview.json["ready_count"] == 2
    assert [item["binding_id"] for item in preview.json["items"]] == ["GH-C01", "GH-001"]
    started = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "c" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202, started.json
    workflow._worker.join(5)
    state = client.get(f"/api/testing/batches/{started.json['batch_run_id']}",
        base_url=BASE, headers=headers).json
    assert state["status"] == "completed" and state["target_request_count"] == 2
    results = client.get(f"/api/testing/batches/{started.json['batch_run_id']}/results",
        base_url=BASE, headers=headers).json["results"]
    assert [row["verdict"] for row in results] == ["PASS", "FAIL"]
    assert len(requests) == 3  # One probe and two distinct native inputs.
    for row, expected in zip(results, ("GH-C01", "GH-001")):
        report = next((workflow.dispatcher.output_root / row["report_run_id"]).glob("native-*.secagent.json"))
        normalized = normalize_report_bytes(report.read_bytes())
        assert normalized.imported_provenance.binding_id == expected
        assert normalized.observation.response_completeness.state == "complete"
        assert normalized.security.verdict == row["verdict"]
        assert normalized.imported_provenance.evidence_provenance == "synthetic_mock"


def test_unreviewed_indirect_claim_stays_unavailable_and_no_text_is_invented(tmp_path, monkeypatch):
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "ready" if prompt == "Reply with one word: ready." else None,
            "tool_calls": []}, "finish_reason": "tool_calls" if prompt != "Reply with one word: ready." else "stop"}]})
    client, headers, workflow, _, target, _, _, selection = setup(
        tmp_path, monkeypatch, answer_override=answer)
    post(client, "connection-checks", {"target_id": target["id"],
        "profile_revision": target["profile_revision"], "policy_ref": target["policy_ref"]}, headers)
    preview = post(client, "batches/preview", selection, headers).json
    assert preview["items"][0]["evaluation_readiness"] == "unavailable"
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "d" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    workflow._worker.join(5)
    results = client.get(f"/api/testing/batches/{started.json['batch_run_id']}/results",
        base_url=BASE, headers=headers).json
    row = results["results"][0]
    assert row["verdict"] == "INCONCLUSIVE" and row["response_complete"] is None
    report = next((workflow.dispatcher.output_root / row["report_run_id"]).glob("native-*.secagent.json"))
    normalized = normalize_report_bytes(report.read_bytes())
    assert normalized.observation.response_preview is None
    assert normalized.observation.response_completeness.state == "unknown"
    assert any(e.kind == "http_response_metadata" and e.details.get("finish_reason") == "tool_calls"
               and e.details.get("assistant_content_present") is False
               for e in normalized.observation.evidence)


def test_native_attack_stays_blocked_without_persisted_clean_pass(tmp_path, monkeypatch):
    control = load_text_binding("GH-C01")
    attack = load_text_binding("GH-001")
    def answer(request):
        return httpx.Response(200, json={"choices": [{"message": {"content": "A greeting, not a summary."},
                                                      "finish_reason": "stop"}]})
    client, headers, workflow, _, target, _, requests, selection = setup(
        tmp_path, monkeypatch, answer_override=answer)
    ds = normalize_dataset(json.dumps({"testcases": [
        {"id": "control", "prompt": control.test_input.prompt},
        {"id": "attack", "prompt": attack.test_input.prompt}]}).encode(), "baseline-gate.json")
    workflow.dataset_repository.save_dataset(ds)
    selection.update(dataset_id=ds.dataset_id,
        testcase_ids=[case.internal_id for case in ds.testcases], total_request_budget=2)
    solo = selection | {"testcase_ids": [ds.testcases[1].internal_id], "total_request_budget": 1}
    assert post(client, "batches/preview", solo, headers).json["items"][0]["reason"] == (
        "clean_baseline_required_in_same_batch")
    post(client, "connection-checks", {"target_id": target["id"],
        "profile_revision": target["profile_revision"], "policy_ref": target["policy_ref"]}, headers)
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "e" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    workflow._worker.join(5)
    results = client.get(f"/api/testing/batches/{started.json['batch_run_id']}/results",
        base_url=BASE, headers=headers).json["results"]
    assert [row["verdict"] for row in results] == ["INCONCLUSIVE", None]
    assert [row["status"] for row in results] == ["completed", "blocked"]
    assert results[1]["reason"] == "clean_baseline_not_confirmed"
    assert results[1]["report_run_id"] is None
    assert len(requests) == 2  # Benign probe and control; attack was not sent.
