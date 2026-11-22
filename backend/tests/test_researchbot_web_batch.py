"""Real Workflow API + BatchOrchestrator + Runner, with mock target transport."""
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json
import re
import socket
from threading import Event, Thread
from time import sleep

import httpx
import pytest

from backend.scripts.serve_asi01_web_lab import handler_for
from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig
from workflow.web_lab_assessment import WebLabAssessment
from workflow.web_lab_runtime import CHAT, TARGET
from workflow.web_live_batch import ResearchBotWebBatchWorkflow
from workflow.web_mock_batch import WEB_ATTACK, WEB_CONTROL


BASE = "http://127.0.0.1:8092"
SECRET = "researchbot-web-batch-operator-" + "x" * 32


class LocalWebLabRuntime:
    provenance = "synthetic_mock"

    def __init__(self, root: Path):
        self.root = root
        self.assessments = []

    def identity(self):
        return {"images": {"dvaa_image": "sha256:" + "a" * 64},
                "fixture_origin": "isolated_loopback_test", "contract": "mock_only"}

    def ready(self):
        return True

    @contextmanager
    def open(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        server.daemon_threads = True
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        assessment = WebLabAssessment.create(self.root, origin, TARGET, "127.0.0.1")
        self.assessments.append(assessment)
        server.RequestHandlerClass = handler_for(assessment)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield assessment
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


@pytest.fixture(autouse=True)
def no_external_target_network(monkeypatch):
    original = socket.socket.connect
    def local_only(sock, address):
        if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "localhost"}:
            pytest.fail("Unexpected outbound network access")
        return original(sock, address)
    monkeypatch.setattr(socket.socket, "connect", local_only)


def setup(tmp_path, *, fetch=True, callback=True, gate=None, status_code=200,
          port=8092, delay_seconds=0, wait_for_cancellation=False,
          endpoint=CHAT, review_target=True, create_target=True):
    calls = []
    cancellation = {}
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        calls.append(prompt)
        if prompt == "Reply with one word: ready.":
            return httpx.Response(200, json={"choices": [{"message": {
                "content": "ready"}, "finish_reason": "stop"}]})
        url = prompt.split()[1]
        assert re.fullmatch(r"http://127\.0\.0\.1:\d+/page/(?:control|attack)/[a-f0-9]{32}", url)
        if fetch:
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=3) as client:
                page = client.get(url)
                assert page.status_code == 200
                if "/attack/" in url and callback:
                    receipt = re.search(r"http://127\.0\.0\.1:\d+/collector/[a-f0-9]{32}/[a-f0-9]{32}", page.text)
                    assert receipt and client.get(receipt.group()).status_code == 200
        if gate is not None and "/control/" in url:
            gate[0].set()
            assert gate[1].wait(5)
        if wait_for_cancellation and "/control/" in url:
            for _ in range(200):
                if cancellation["requested"]():
                    break
                sleep(0.05)
            else:
                raise RuntimeError("Offline browser cancellation was not received.")
        if delay_seconds:
            sleep(delay_seconds)
        return httpx.Response(status_code, json={"choices": [{"message": {
            "content": "Synthetic weather station observation."}, "finish_reason": "stop"}]})

    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="web-lab-research", targets=[]), tmp_path / "operator-data",
        local_single_user=True)
    draft = None
    if create_target:
        row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
            id=TARGET, name="Restricted ResearchBot Web Lab", platform_id="dvaa",
            platform_name="DVAA", endpoint=endpoint, protocol="openai-chat",
            model="researchbot", timeout_seconds=3)))
        if review_target:
            row = catalog.review_profile(ReviewProfile(target_id=row["id"],
                profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
                endpoint=row["endpoint"], protocol=row["protocol"], model=row["default_model"],
                capabilities=["chat"], authorization_confirmed=True))
        draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint",
            "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
        draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(answer), output_boundary=output)
    runtime = LocalWebLabRuntime(tmp_path / "assessments")
    workflow = ResearchBotWebBatchWorkflow(dispatcher, runtime, test_only_mock=True)
    cancellation["requested"] = workflow.orchestrator.cancellation_requested
    client = create_app(catalog, port=port, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_service=workflow).test_client()
    base = f"http://127.0.0.1:{port}"
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    headers = {"Origin": base, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": SECRET}
    return client, headers, workflow, runtime, draft, calls


def post(client, path, body, headers):
    return client.post("/api/testing/" + path, base_url=BASE, json=body, headers=headers)


def get(client, path, headers):
    return client.get("/api/testing/" + path, base_url=BASE, headers=headers)


def run(client, headers, draft, *, ids=(WEB_ATTACK,), submission="a" * 32):
    selected = dict(target=draft, testcase_ids=list(ids), total_request_budget=2,
                    evaluation_mode="rule_only")
    plan = post(client, "batches/preview", selected, headers)
    assert plan.status_code == 200, plan.json
    start = post(client, "batches", selected | {"expected_plan_id": plan.json["plan_id"],
        "submission_id": submission, "authorization_confirmed": True}, headers)
    assert start.status_code == 202, start.json
    identity = start.json["batch_run_id"]
    for _ in range(120):
        status = get(client, f"batches/{identity}", headers)
        if status.status_code == 200 and status.json["status"] in {
                "completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            return plan.json, status.json, get(client, f"batches/{identity}/results", headers).json
        sleep(0.05)
    pytest.fail("Restricted Web Lab mock integration did not terminate")


def test_verified_preflight_and_callback_fail_with_native_report(tmp_path):
    client, headers, workflow, runtime, draft, calls = setup(tmp_path)
    plan, status, results = run(client, headers, draft, ids=(WEB_CONTROL, WEB_ATTACK))
    assert [(r["testcase_id"], r["status"]) for r in plan["items"]] == [
        (WEB_CONTROL, "blocked"), (WEB_ATTACK, "ready")]
    row = results["results"][1]
    assert status["target_request_count"] == status["request_budget_consumed"] == 2
    assert row["status"] == "completed" and row["verdict"] == "FAIL"
    assert row["request_count"] == 2 and len(calls) == 2
    assessment = runtime.assessments[0]
    preflight = json.loads((assessment.directory / "preflight-result.json").read_text())
    assert preflight["status"] == "verified" and preflight["security_verdict"] is None
    assert json.loads((assessment.directory / "attack-observation.json").read_text())[
        "evidence"]["data"]["correlation_valid"] is True
    report_path = (workflow.dispatcher.output_root / row["report_run_id"] /
        f"native-{WEB_ATTACK}-{row['report_run_id']}.secagent.json")
    report = json.loads(report_path.read_text())
    assert report["source_provenance"] == "synthetic_mock"
    assert report["evaluation"]["final_verdict"] == "FAIL"
    assert row["report_sha256"] == __import__("hashlib").sha256(report_path.read_bytes()).hexdigest()


@pytest.mark.parametrize("fetch,callback,expected_status,expected_verdict,count", [
    (False, True, "blocked", None, 1),
    (True, False, "completed", "INCONCLUSIVE", 2),
])
def test_preflight_and_missing_callback_semantics(
        tmp_path, fetch, callback, expected_status, expected_verdict, count):
    client, headers, _, runtime, draft, calls = setup(tmp_path, fetch=fetch, callback=callback)
    _, status, results = run(client, headers, draft)
    row = results["results"][0]
    assert row["status"] == expected_status and row["verdict"] == expected_verdict
    assert row["request_count"] == status["target_request_count"] == count
    assert len(calls) == count
    preflight = json.loads((runtime.assessments[0].directory / "preflight-result.json").read_text())
    assert preflight["security_verdict"] is None


def test_cancel_after_preflight_and_reject_unauthorized_or_stale(tmp_path):
    gate = Event(), Event()
    client, headers, workflow, _, draft, calls = setup(tmp_path, gate=gate)
    selected = dict(target=draft, testcase_ids=[WEB_ATTACK], total_request_budget=2,
                    evaluation_mode="rule_only")
    plan = post(client, "batches/preview", selected, headers)
    assert plan.status_code == 200
    assert post(client, "batches/preview", selected, {"Origin": BASE}).status_code == 403
    assert post(client, "batches/preview", selected,
        headers | {"Origin": "http://untrusted.example"}).status_code == 403
    assert post(client, "batches/preview", selected | {"target": draft | {
        "profile_revision": "f" * 64}}, headers).status_code == 409
    assert post(client, "batches/preview", selected | {"target": draft | {
        "endpoint": "http://127.0.0.1:7015/v1/chat/completions"}}, headers).status_code == 409
    assert post(client, "batches", selected | {"expected_plan_id": "f" * 64,
        "submission_id": "b" * 32, "authorization_confirmed": True}, headers).status_code == 409
    start = post(client, "batches", selected | {"expected_plan_id": plan.json["plan_id"],
        "submission_id": "c" * 32, "authorization_confirmed": True}, headers)
    assert start.status_code == 202
    identity = start.json["batch_run_id"]
    try:
        assert gate[0].wait(5)
        assert post(client, f"batches/{identity}/cancel", {}, headers).status_code == 200
    finally:
        gate[1].set()
    for _ in range(120):
        status = get(client, f"batches/{identity}", headers).json
        if status["status"] in {"cancelled", "completed", "failed", "partially_completed"}:
            break
        sleep(0.05)
    assert status["status"] == "cancelled" and status["target_request_count"] == 1
    assert len(calls) == 1
    row = get(client, f"batches/{identity}/results", headers).json["results"][0]
    assert row["status"] == "cancelled" and row["verdict"] is None
    assert post(client, "batches", selected | {"expected_plan_id": plan.json["plan_id"],
        "submission_id": "c" * 32, "authorization_confirmed": True}, headers).status_code == 409
    assert get(client, f"batches/{'f' * 32}", headers).status_code == 404


def test_target_execution_error_is_not_security_fail(tmp_path):
    client, headers, _, runtime, draft, calls = setup(tmp_path, status_code=500)
    _, status, results = run(client, headers, draft)
    row = results["results"][0]
    assert len(calls) == 1 and status["target_request_count"] == 1
    assert row["status"] == "error" and row["verdict"] == "ERROR"
    preflight = json.loads((runtime.assessments[0].directory / "preflight-result.json").read_text())
    assert preflight["status"] == "unverified" and preflight["security_verdict"] is None


def test_default_api_has_no_web_batch_routes(tmp_path):
    client, headers, workflow, _, draft, calls = setup(tmp_path)
    default = create_app(workflow.catalog, dispatcher=workflow.dispatcher,
        operator_secret=SECRET, local_single_user=True).test_client()
    health = default.get("/api/testing/health", base_url=BASE).json
    assert health["web_lab_batch_enabled"] is False
    selected = dict(target=draft, testcase_ids=[WEB_ATTACK], total_request_budget=2,
                    evaluation_mode="rule_only")
    assert post(default, "batches/preview", selected, headers | {
        "X-SecAgent-Validation": health["validation_nonce"]}).status_code == 403
    assert not calls


@pytest.mark.parametrize("endpoint,review_target,change,expected", [
    ("http://127.0.0.1:7015/v1/chat/completions", True, {}, "web_lab_endpoint_mismatch"),
    (CHAT, False, {}, "web_lab_target_not_reviewed"),
    (CHAT, True, {"profile_revision": "f" * 64}, "web_lab_profile_revision_mismatch"),
    (CHAT, True, {"target_id": "unknown-web-lab"}, "web_lab_target_not_found"),
])
def test_preview_explains_operator_target_mismatch(
        tmp_path, endpoint, review_target, change, expected):
    client, headers, _, _, draft, calls = setup(tmp_path, endpoint=endpoint,
                                                  review_target=review_target)
    selected = dict(target=draft | change, testcase_ids=[WEB_ATTACK],
                    total_request_budget=2, evaluation_mode="rule_only")
    response = post(client, "batches/preview", selected, headers)
    assert response.status_code == 409
    assert response.json["error"]["code"] == expected
    assert response.json["error"]["message"] != (
        "Workflow request rejected; inspect the current target status and operator configuration.")
    assert not calls
