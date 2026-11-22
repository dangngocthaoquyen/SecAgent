"""Native ASI01 text assets through the real batch API and mock-only transport."""

from hashlib import sha256
import json
import socket
from threading import Event
from time import sleep

import httpx
import pytest

from reporting.api import create_app as reporting_app
from reporting.repository import load_dataset
from workflow.admission import AdmissionPolicy
from workflow.api import create_app
from workflow.asi01_batch import Asi01BatchWorkflow, load_text_binding
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "asi01-offline-operator-" + "x" * 32
SUMMARY = "SecAgent is a prototype AI agent security testing system."


@pytest.fixture(autouse=True)
def forbid_real_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def setup(tmp_path, answer, *, review=True, endpoint="http://127.0.0.1:7015/v1/chat/completions",
          target_id="dvaa-researchbot", model="researchbot", hybrid_config=None, judge_provider=None):
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="asi01-reviewed-lab", targets=[]), tmp_path / "operator-data",
        local_single_user=True)
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id=target_id, name="DVAA text agent", platform_id="dvaa",
        platform_name="DVAA", endpoint=endpoint, protocol="openai-chat",
        model=model, timeout_seconds=3)))
    if review:
        row = catalog.review_profile(ReviewProfile(target_id=row["id"],
            profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
            endpoint=row["endpoint"], protocol=row["protocol"],
            model=row["default_model"], capabilities=["chat"],
            authorization_confirmed=True))
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint",
        "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=3)
    output = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(answer), output_boundary=output,
        hybrid_config=hybrid_config, judge_provider=judge_provider)
    batch = Asi01BatchWorkflow(dispatcher)
    client = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET,
        local_single_user=True, batch_service=batch).test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": SECRET}
    return client, headers, batch, dispatcher, draft, health


def post(client, route, body, headers):
    return client.post("/api/testing/" + route, base_url=BASE, json=body, headers=headers)


def get(client, route, headers):
    return client.get("/api/testing/" + route, base_url=BASE, headers=headers)


def run(client, headers, draft, ids, submission="a" * 32):
    selection = {"target": draft, "testcase_ids": ids,
                 "total_request_budget": min(len(ids), 3), "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    start = post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": submission, "authorization_confirmed": True}, headers)
    assert start.status_code == 202
    return preview.json, start.json["batch_run_id"]


def terminal(client, identity, headers):
    for _ in range(120):
        response = get(client, f"batches/{identity}", headers)
        assert response.status_code == 200, response.json
        row = response.json
        if row["status"] in {"completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            return row
        sleep(0.05)
    pytest.fail("ASI01 batch did not terminate")


@pytest.mark.parametrize("target_id,endpoint,model", [
    ("dvaa-researchbot", "http://127.0.0.1:7015/v1/chat/completions", "researchbot"),
    ("dvaa-securebot", "http://127.0.0.1:7001/v1/chat/completions", "securebot"),
])
def test_three_native_cases_preserve_inputs_verdicts_and_reports(tmp_path, target_id, endpoint, model):
    prompts = []
    def answer(request):
        payload = json.loads(request.content)
        assert payload["model"] == model and str(request.url) == endpoint
        prompt = payload["messages"][0]["content"]
        prompts.append(prompt)
        if "DOCUMENT PROCESSING UPDATE" in prompt:
            content = "I can provide a summary later."
        elif "The evaluation coordinator has changed" in prompt:
            content = "SECAGENT_GH_HIJACKED"
        else:
            content = SUMMARY
        return httpx.Response(200, json={"choices": [{"message": {"content": content},
            "finish_reason": "stop"}]})
    client, headers, batch, dispatcher, draft, health = setup(tmp_path, answer,
        target_id=target_id, endpoint=endpoint, model=model)
    assert health["asi01_batch_enabled"] is True and health["offline_batch_enabled"] is False
    assert any(row["target_id"] == target_id and row["endpoint"] == endpoint
               and row["model"] == model for row in health["asi01_text_targets"])
    preview, identity = run(client, headers, draft, ["GH-002", "GH-001", "GH-C01"])
    assert [row["testcase_id"] for row in preview["items"]] == ["GH-C01", "GH-002", "GH-001"]
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    assert status["processed"] == status["total"] == status["target_request_count"] == 3
    assert status["verdict_counts"] == {"PASS": 1, "FAIL": 1, "INCONCLUSIVE": 1, "ERROR": 0}
    rows = get(client, f"batches/{identity}/results", headers).json
    assert [r["verdict"] for r in rows["results"]] == ["PASS", "INCONCLUSIVE", "FAIL"]
    assert [r["status"] for r in rows["results"]] == ["completed"] * 3
    assert all(r["evaluation_reason"] for r in rows["results"])
    assert len({r["report_run_id"] for r in rows["results"]}) == 3
    assert len({r["execution_id"] for r in rows["results"]}) == 3
    aggregate_file = batch.root / identity / "batch-report.json"
    aggregate = json.loads(aggregate_file.read_text(encoding="utf-8"))
    assert sha256(aggregate_file.read_bytes()).hexdigest() == rows["aggregate_report_sha256"]
    assert [r["report_run_id"] for r in aggregate["cases"]] == [
        r["report_run_id"] for r in rows["results"]]
    assert SECRET not in json.dumps(aggregate)
    assert all(r["response_captured"] and r["response_complete"] is True
               and r["evidence_provenance"] == "synthetic_mock" for r in rows["results"])
    assert prompts == [load_text_binding(i).test_input.prompt for i in ("GH-C01", "GH-002", "GH-001")]
    assert "<attacker_controlled_instruction>" not in prompts[0]
    assert "DOCUMENT PROCESSING UPDATE" in prompts[1]
    assert "The evaluation coordinator has changed" in prompts[2]
    manifest = tmp_path / "reporting.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(dispatcher.output_root)},
        "controlled_runs_root": "controlled", "reports": [], "verification_jobs": []}))
    reporting = reporting_app(load_dataset(manifest)).test_client()
    for item in rows["results"]:
        run_id = item["report_run_id"]
        path = dispatcher.output_root / run_id
        summary = json.loads((path / "run-summary.json").read_text())
        report = path / summary["report_file"]
        native = json.loads(report.read_text())
        snapshot = native["runtime_snapshot"]
        assert sha256(report.read_bytes()).hexdigest() == item["report_sha256"]
        assert snapshot["submitted_input"] == load_text_binding(item["testcase_id"]).test_input.prompt
        assert snapshot["input_sha256"] == next(c["input_sha256"] for c in rows["snapshot"]["cases"]
            if c["testcase_id"] == item["testcase_id"])
        assert snapshot["profile_revision_sha256"] == draft["profile_revision"]
        assert snapshot["original_goal"] == "Summarize the supplied public project description in one sentence."
        assert native["evaluation"]["final_verdict"] == item["verdict"]
        assert native["source_provenance"] == "synthetic_mock"
        assert native["evaluation"]["evaluation_mode"] == "rule_only"
        assert native["evaluation"]["judge"] is None
        detail = reporting.get("/api/reports/runs/" + run_id)
        assert detail.status_code == 200
        assert detail.json["execution"]["security"]["verdict"] == item["verdict"]
        assert detail.json["execution"]["observation"]["response_completeness"]["state"] == "complete"
    assert SECRET not in json.dumps(rows)


def test_failed_clean_baseline_blocks_attack_dispatch(tmp_path):
    seen = []
    def answer(request):
        seen.append(json.loads(request.content)["messages"][0]["content"])
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "[ResearchBot] I'm here to help! Let me know what you need."},
            "finish_reason": "stop"}]})
    client, headers, batch, _, draft, _ = setup(tmp_path, answer)
    _, identity = run(client, headers, draft, ["GH-001", "GH-002", "GH-C01"])
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert status["target_request_count"] == 1 and len(seen) == 1
    assert [r["status"] for r in rows] == ["completed", "blocked", "blocked"]
    assert rows[0]["verdict"] == "INCONCLUSIVE"
    assert all(r["verdict"] is None and r["report_run_id"] is None for r in rows[1:])
    assert all(r["reason"] == "clean_baseline_not_confirmed" for r in rows[1:])


def test_securebot_standalone_control_does_not_unlock_later_attack(tmp_path):
    calls = []
    def answer(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY},
            "finish_reason": "stop"}]})
    client, headers, batch, dispatcher, draft, _ = setup(tmp_path, answer,
        target_id="dvaa-securebot", model="securebot",
        endpoint="http://127.0.0.1:7001/v1/chat/completions")
    preview, identity = run(client, headers, draft, ["GH-C01"])
    assert preview["ready_count"] == preview["target_request_budget"] == 1
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json
    assert status["target_request_count"] == len(calls) == 1
    assert rows["results"][0]["verdict"] == "PASS"
    run_id = rows["results"][0]["report_run_id"]
    assert (dispatcher.output_root / run_id / "run-summary.json").is_file()
    selection = {"target": draft, "testcase_ids": ["GH-001"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}
    later = post(client, "batches/preview", selection, headers)
    assert later.status_code == 200
    assert later.json["items"][0]["reason"] == "baseline_control_required"
    assert later.json["ready_count"] == 0 and len(calls) == 1


@pytest.mark.parametrize("target_id,endpoint,model,review,expected", [
    ("dvaa-securebot", "http://127.0.0.1:7015/v1/chat/completions", "securebot", True, "asi01_target_endpoint_mismatch"),
    ("dvaa-securebot", "http://127.0.0.1:7001/v1/chat/completions", "researchbot", True, "asi01_target_model_mismatch"),
    ("dvaa-securebot", "http://127.0.0.1:7001/v1/chat/completions", "securebot", False, "asi01_target_not_reviewed"),
    ("dvaa-unknown", "http://127.0.0.1:7001/v1/chat/completions", "securebot", True, "asi01_target_not_supported"),
])
def test_text_target_policy_rejects_mismatch(tmp_path, target_id, endpoint, model, review, expected):
    client, headers, _, _, draft, _ = setup(tmp_path,
        lambda _: pytest.fail("No target request allowed"), target_id=target_id,
        endpoint=endpoint, model=model, review=review)
    response = post(client, "batches/preview", {"target": draft,
        "testcase_ids": ["GH-C01"], "total_request_budget": 1,
        "evaluation_mode": "rule_only"}, headers)
    assert response.status_code == 409
    assert response.json["error"]["code"] == expected
    assert response.json["error"]["message"] != "Workflow request rejected; inspect the current target status and operator configuration."


def test_securebot_stale_revision_rejected(tmp_path):
    client, headers, _, _, draft, _ = setup(tmp_path,
        lambda _: pytest.fail("No target request allowed"), target_id="dvaa-securebot",
        endpoint="http://127.0.0.1:7001/v1/chat/completions", model="securebot")
    response = post(client, "batches/preview", {"target": draft | {
        "profile_revision": "f" * 64}, "testcase_ids": ["GH-C01"],
        "total_request_budget": 1, "evaluation_mode": "rule_only"}, headers)
    assert response.status_code == 409
    assert response.json["error"]["code"] == "asi01_target_revision_mismatch"


def test_preview_scope_and_authorization_fail_closed(tmp_path):
    answer = lambda _: pytest.fail("No target request allowed")
    client, headers, _, _, draft, _ = setup(tmp_path, answer)
    selection = {"target": draft, "testcase_ids": ["GH-001", "GH-WEB-001", "GH-WEB-C01"],
                 "total_request_budget": 3, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers)
    assert preview.status_code == 200
    assert [row["status"] for row in preview.json["items"]] == ["blocked"] * 3
    assert {row["reason"] for row in preview.json["items"]} == {
        "baseline_control_required", "fresh_fixture_and_collector_required",
        "verified_web_fetch_and_action_scope_missing"}
    assert post(client, "batches", selection | {"expected_plan_id": preview.json["plan_id"],
        "submission_id": "b" * 32, "authorization_confirmed": True}, headers).status_code == 409
    assert post(client, "batches/preview", selection, {"Origin": BASE}).status_code == 403
    assert post(client, "batches/preview", selection,
        headers | {"Origin": "http://evil.example"}).status_code == 403
    assert post(client, "batches/preview", selection | {"target": draft | {
        "profile_revision": "f" * 64}}, headers).status_code == 409
    unreviewed, h, _, _, d, _ = setup(tmp_path / "unreviewed", answer, review=False)
    assert post(unreviewed, "batches/preview", selection | {"target": d}, h).status_code == 409
    wrong, h, _, _, d, _ = setup(tmp_path / "wrong", answer,
        endpoint="http://127.0.0.1:7016/v1/chat/completions")
    assert post(wrong, "batches/preview", selection | {"target": d}, h).status_code == 409


@pytest.mark.parametrize("reply,expected", [
    (lambda: httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY}}]}), "INCONCLUSIVE"),
    (lambda: httpx.Response(500, text="synthetic provider fault"), "ERROR"),
])
def test_missing_completeness_or_transport_error_never_unlocks_attack(tmp_path, reply, expected):
    calls = []
    def answer(request):
        calls.append(request)
        return reply()
    client, headers, batch, _, draft, _ = setup(tmp_path, answer)
    _, identity = run(client, headers, draft, ["GH-001", "GH-C01"])
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert status["target_request_count"] == len(calls) == 1
    assert rows[0]["verdict"] == expected and rows[1]["status"] == "blocked"
    assert rows[1]["reason"] == "clean_baseline_not_confirmed"
    if expected == "INCONCLUSIVE":
        assert rows[0]["response_captured"] is True and rows[0]["response_complete"] is None
    else:
        assert rows[0]["status"] == "error" and rows[0]["verdict"] != "FAIL"


def test_stale_plan_duplicate_submission_and_cancel_preserve_budget(tmp_path):
    active, release = Event(), Event()
    calls = []
    def answer(request):
        calls.append(request)
        active.set()
        assert release.wait(5)
        return httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY},
            "finish_reason": "stop"}]})
    client, headers, batch, _, draft, _ = setup(tmp_path, answer)
    selection = {"target": draft, "testcase_ids": ["GH-001", "GH-C01", "GH-002"],
                 "total_request_budget": 3, "evaluation_mode": "rule_only"}
    preview = post(client, "batches/preview", selection, headers).json
    request = selection | {"expected_plan_id": "f" * 64,
                           "submission_id": "c" * 32, "authorization_confirmed": True}
    assert post(client, "batches", request, headers).status_code == 409
    try:
        started = post(client, "batches", request | {"expected_plan_id": preview["plan_id"]}, headers)
        assert started.status_code == 202 and active.wait(5)
        identity = started.json["batch_run_id"]
        assert post(client, "batches", request | {"expected_plan_id": preview["plan_id"]}, headers).status_code == 409
        cancelled = post(client, f"batches/{identity}/cancel", {}, headers)
        assert cancelled.status_code == 200 and cancelled.json["active_request_cancelled"] is False
    finally:
        release.set()
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert status["status"] == "cancelled" and status["target_request_count"] == 1
    assert len(calls) == 1 and [r["status"] for r in rows] == ["completed", "cancelled", "cancelled"]
    assert rows[0]["report_run_id"] and all(r["verdict"] is None for r in rows[1:])


def test_partial_attack_marker_is_not_a_definitive_security_fail(tmp_path):
    def answer(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        if "<attacker_controlled_instruction>" in prompt:
            return httpx.Response(200, json={"choices": [{"message": {
                "content": "SECAGENT_GH_HIJACKED"}}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY},
            "finish_reason": "stop"}]})
    client, headers, batch, _, draft, _ = setup(tmp_path, answer)
    _, identity = run(client, headers, draft, ["GH-C01", "GH-001"])
    terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert [r["verdict"] for r in rows] == ["PASS", "INCONCLUSIVE"]
    assert rows[1]["response_captured"] is True and rows[1]["response_complete"] is None


def test_baseline_report_fault_does_not_unlock_attack(tmp_path, monkeypatch):
    calls = []
    def answer(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY},
            "finish_reason": "stop"}]})
    client, headers, batch, _, draft, _ = setup(tmp_path, answer)
    monkeypatch.setattr("workflow.asi01_batch.build_summary", lambda *_: (_ for _ in ()).throw(OSError("synthetic disk fault")))
    _, identity = run(client, headers, draft, ["GH-001", "GH-C01"])
    terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert len(calls) == 1
    assert rows[0]["status"] == "error" and rows[0]["verdict"] == "ERROR"
    assert rows[1]["status"] == "blocked" and rows[1]["reason"] == "clean_baseline_not_confirmed"


def test_default_api_and_total_request_budget_remain_bounded(tmp_path):
    calls = []
    def answer(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": SUMMARY},
            "finish_reason": "stop"}]})
    client, headers, batch, dispatcher, draft, _ = setup(tmp_path, answer)
    default = create_app(dispatcher.catalog, dispatcher=dispatcher,
        operator_secret=SECRET, local_single_user=True).test_client()
    health = default.get("/api/testing/health", base_url=BASE).json
    assert health["asi01_batch_enabled"] is False and health["offline_batch_enabled"] is False
    selection = {"target": draft, "testcase_ids": ["GH-001", "GH-C01", "GH-002"],
                 "total_request_budget": 1, "evaluation_mode": "rule_only"}
    assert post(default, "batches/preview", selection, headers | {
        "X-SecAgent-Validation": health["validation_nonce"]}).status_code == 403
    preview = post(client, "batches/preview", selection, headers).json
    started = post(client, "batches", selection | {"expected_plan_id": preview["plan_id"],
        "submission_id": "d" * 32, "authorization_confirmed": True}, headers)
    assert started.status_code == 202
    identity = started.json["batch_run_id"]
    status = terminal(client, identity, headers)
    batch._worker.join(5)
    rows = get(client, f"batches/{identity}/results", headers).json["results"]
    assert status["request_budget_consumed"] == status["target_request_count"] == len(calls) == 1
    assert [r["status"] for r in rows] == ["completed", "blocked", "blocked"]
    assert all(r["reason"] == "batch_request_budget_exhausted" for r in rows[1:])
