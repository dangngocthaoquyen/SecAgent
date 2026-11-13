"""Controlled local MockTransport exercises the real Runner and report writer."""

from datetime import datetime, timezone, timedelta
from hashlib import sha256
import json
from pathlib import Path
import re
from uuid import uuid4

import httpx
import pytest

from test_workflow_targets import config, setup
from workflow.admission import AdmissionPolicy, AdmissionRequest, ExecutionGrant
from workflow.api import create_app
from workflow.catalog import TargetCatalog
from workflow.dispatch import ControlledDispatcher, sanitized
from workflow.fixture_runtime import LocalMockFixtureRuntime
from workflow.models import CatalogConfig
from testing import RunnerEvaluationConfig
from test_runner_judge_integration import FakeJudge


ANSWER = "SecAgent is a prototype AI agent security testing system."
SECRET = "s" * 40


def environment(tmp_path, *, handler=None, authorized=True, secret=SECRET,
                case_id="GH-C01", fixture_runtime=None, policy_revision="deny-by-default",
                hybrid_config=None, judge_provider=None):
    catalog = TargetCatalog(CatalogConfig.model_validate(config()))
    _, draft, _ = setup()
    selection = AdmissionRequest(target=draft, asi_categories=["ASI01"], testcase_ids=[case_id])
    from workflow.admission import AdmissionService
    asset = AdmissionService(catalog).assess(selection)["asset_sha256"][case_id]
    grants = [ExecutionGrant(target_id=draft["target_id"], profile_revision=draft["profile_revision"],
        policy_ref=draft["policy_ref"], testcase_id=case_id, asset_sha256=asset,
        scope="security_test_execution", expires_at=datetime.now(timezone.utc)+timedelta(minutes=15),
        authorization_id=uuid4().hex if case_id == "GH-WEB-001" else None)] if authorized else []
    policy = AdmissionPolicy(revision=policy_revision, grants=grants)
    seen = []
    def mock(request):
        seen.append(request)
        if handler:
            return handler(request)
        return httpx.Response(200, json={"choices":[{"message":{"content":ANSWER}}]})
    boundary = tmp_path / "selected-results"
    boundary.mkdir(parents=True)
    dispatcher = ControlledDispatcher(catalog, policy, boundary / "runs", operator_secret=secret,
        transport=httpx.MockTransport(mock), output_boundary=boundary, fixture_runtime=fixture_runtime,
        hybrid_config=hybrid_config, judge_provider=judge_provider)
    client = create_app(catalog, admission_policy=policy, dispatcher=dispatcher).test_client()
    base = "http://127.0.0.1:8092"
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    headers = {"Origin":base,"X-SecAgent-Validation":nonce,"X-SecAgent-Operator":secret}
    return client, selection, headers, dispatcher, seen


def post(client, path, selection, headers):
    return client.post("/api/testing/"+path, base_url=headers["Origin"],
        json=selection.model_dump(mode="json"), headers=headers)


def test_successful_mock_target_runner_report_and_single_use(tmp_path):
    client, selection, headers, dispatcher, seen = environment(tmp_path)
    health = client.get("/api/testing/health", base_url=headers["Origin"]).json
    assert health["target_network_access"] and health["mode"] == "controlled_execution_enabled"
    first = post(client,"readiness/preview",selection,headers).json
    assert first["decision"] == "ready_for_admission" and not first["dispatch_available"]
    selection = selection.model_copy(update={"expected_plan_id":first["plan_id"]})
    admitted = post(client,"admissions",selection,headers).json
    assert admitted["admitted"] and admitted["dispatch_available"]
    result = post(client,"runs",selection,headers).json
    assert result["execution_status"] == "completed" and result["historical_verdict"] == "PASS"
    assert result["target_request_count"] == 1 and result["report_persisted"]
    assert len(seen) == 1 and str(seen[0].url) == selection.target.endpoint
    assert seen[0].method == "POST"
    assert json.loads(seen[0].content)["messages"][0]["content"]
    directory = dispatcher.output_root / result["run_id"]
    reports = list(directory.glob("*.secagent.json"))
    assert len(reports) == 1 and sha256(reports[0].read_bytes()).hexdigest() == result["report_sha256"]
    native = json.loads(reports[0].read_text(encoding="utf-8"))
    assert native["engine"] == "native" and native["evaluation"]["final_verdict"] == "PASS"
    assert native["evaluation"]["evaluation_mode"] == "rule_only"
    assert native["evaluation"]["judge_budget"] is None
    assert native["evaluation"]["observation"]["response_text"] == ANSWER
    assert native["evaluation"]["execution"]["response_complete"] is None
    assert (directory/"run-summary.json").is_file()
    duplicate = post(client,"runs",selection,headers)
    assert duplicate.status_code == 409 and len(seen) == 1
    fresh_process = ControlledDispatcher(dispatcher.catalog, dispatcher.policy,
        dispatcher.output_root, operator_secret=SECRET, transport=httpx.MockTransport(lambda _: (_ for _ in ()).throw(AssertionError("No second request"))),
        output_boundary=dispatcher.output_root.parent)
    assert not fresh_process.readiness(selection, admit=True)["dispatch_available"]
    with pytest.raises(Exception, match="already claimed"):
        fresh_process.run(selection)


def test_auth_stale_unauthorized_and_scope_reject_before_target(tmp_path):
    client, selection, headers, _, seen = environment(tmp_path)
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    valid = selection.model_copy(update={"expected_plan_id":plan})
    assert post(client,"runs",valid,{**headers,"X-SecAgent-Operator":"wrong"}).status_code == 403
    assert post(client,"runs",valid,{k:v for k,v in headers.items() if k!="X-SecAgent-Validation"}).status_code == 403
    stale = selection.model_copy(update={"expected_plan_id":"a"*64})
    assert post(client,"runs",stale,headers).status_code == 409
    unknown = valid.model_copy(update={"target":valid.target.model_copy(update={"target_id":"unapproved"})})
    assert post(client,"runs",unknown,headers).status_code == 409
    scope = valid.model_copy(update={"testcase_ids":["GH-WEB-001"]})
    assert post(client,"runs",scope,headers).status_code == 409
    assert not seen
    _, selection2, _, dispatcher2, seen2 = environment(tmp_path / "second", authorized=False)
    assert not dispatcher2.readiness(selection2)["admitted"]
    assert not seen2


def test_timeout_and_oversize_report_fail_without_retry(tmp_path):
    def timeout(_):
        raise httpx.ReadTimeout("synthetic timeout")
    client, selection, headers, dispatcher, seen = environment(tmp_path, handler=timeout)
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    response = post(client,"runs",selection.model_copy(update={"expected_plan_id":plan}),headers).json
    assert response["execution_status"] == "failed" and response["target_request_count"] == 1
    assert len(seen) == 1
    assert response["report_persisted"]
    reports = list((dispatcher.output_root/response["run_id"]).glob("*.secagent.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["evaluation"]["final_verdict"] == "ERROR"

    other = tmp_path / "other"; other.mkdir()
    def large(_):
        return httpx.Response(200, content=b"x"*70000)
    client, selection, headers, _, seen = environment(other, handler=large)
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    result = post(client,"runs",selection.model_copy(update={"expected_plan_id":plan}),headers).json
    assert result["execution_status"] == "failed" and len(seen) == 1


def test_target_echo_of_operator_secret_is_redacted_from_native_report(tmp_path):
    def echoed(_):
        return httpx.Response(200, json={"choices":[{"message":{"content":SECRET}}]})
    client, selection, headers, dispatcher, seen = environment(tmp_path, handler=echoed)
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    result = post(client,"runs",selection.model_copy(update={"expected_plan_id":plan}),headers).json
    assert result["report_persisted"] and len(seen) == 1
    report = next((dispatcher.output_root/result["run_id"]).glob("*.secagent.json"))
    assert SECRET not in report.read_text(encoding="utf-8")
    assert "[REDACTED]" in report.read_text(encoding="utf-8")


def test_default_workflow_cannot_execute(tmp_path):
    catalog = TargetCatalog(CatalogConfig.model_validate(config()))
    client = create_app(catalog).test_client()
    base = "http://127.0.0.1:8092"
    nonce = client.get("/api/testing/health",base_url=base).json["validation_nonce"]
    result = client.post("/api/testing/runs",base_url=base,json={},headers={
        "Origin":base,"X-SecAgent-Validation":nonce,"X-SecAgent-Operator":SECRET})
    assert result.status_code == 403 and result.json["error"]["code"] == "execution_disabled"


def _hybrid_fixture(tmp_path, *, response=ANSWER, judge=None, configured=True):
    """Benign GH-C01 through MockTransport and an in-memory fake Pi process."""
    fake = judge or FakeJudge()
    config = RunnerEvaluationConfig(mode="hybrid", judge_enabled=True, max_judge_calls=1) if configured else None
    handler = lambda _: httpx.Response(200, json={"choices": [{"message": {"content": response}}]})
    client, selection, headers, dispatcher, seen = environment(tmp_path, handler=handler,
        hybrid_config=config, judge_provider=fake if configured else None)
    return client, selection.model_copy(update={"evaluation_mode": "hybrid"}), headers, dispatcher, seen, fake


def test_web_report_redaction_preserves_only_structured_integrity_digests():
    digest = "a" * 64
    row = sanitized({"request_sha256": digest, "skill_sha256": digest,
        "runtime_id": digest, "judge_reason": "secret-value"}, secrets_to_remove=("secret-value",))
    assert row["request_sha256"] == row["skill_sha256"] == digest
    assert row["runtime_id"] == "[OPAQUE_REDACTED]"
    assert row["judge_reason"] == "[REDACTED]"
    assert sanitized({"request_sha256": digest}, secrets_to_remove=(digest,))["request_sha256"] == "[REDACTED]"


def test_web_hybrid_constructor_rejects_unbounded_or_untrusted_provider(tmp_path):
    with pytest.raises(ValueError, match="bounded server-owned"):
        environment(tmp_path / "unbounded", hybrid_config=RunnerEvaluationConfig(
            mode="hybrid", judge_enabled=True, max_judge_calls=2), judge_provider=FakeJudge())


def test_cli_hybrid_opt_in_without_operator_configuration_does_not_start(monkeypatch):
    from workflow import api
    monkeypatch.setattr(api, "load_catalog", lambda _: object())
    monkeypatch.setattr(api.Flask, "run", lambda *args, **kwargs: pytest.fail("Server must not start"))
    assert api.main(["--catalog", "unused", "--enable-web-hybrid-judge"]) == 2
    assert api.main(["--catalog", "unused", "--enable-controlled-runs",
                     "--enable-web-hybrid-judge"]) == 2


def _hybrid_run(tmp_path, *, response=ANSWER, judge=None):
    client, selection, headers, dispatcher, seen, fake = _hybrid_fixture(
        tmp_path, response=response, judge=judge)
    preview = post(client, "readiness/preview", selection, headers).json
    assert preview["evaluation_mode"] == "hybrid" and preview["max_judge_calls"] == 1
    selection = selection.model_copy(update={"expected_plan_id": preview["plan_id"]})
    result = post(client, "runs", selection, headers).json
    report_path = next((dispatcher.output_root / result["run_id"]).glob("*.secagent.json"))
    return result, json.loads(report_path.read_text(encoding="utf-8")), report_path, fake, seen, dispatcher


def test_hybrid_is_server_selected_and_binds_plan_identity(tmp_path):
    client, hybrid, headers, _, seen, _ = _hybrid_fixture(tmp_path)
    health = client.get("/api/testing/health", base_url=headers["Origin"]).json
    assert health["evaluation_modes"] == ["rule_only", "hybrid"]
    assert health["judge_configuration"] == "configured_unverified"
    hybrid_plan = post(client, "readiness/preview", hybrid, headers).json["plan_id"]
    rule_plan = post(client, "readiness/preview",
        hybrid.model_copy(update={"evaluation_mode": "rule_only"}), headers).json["plan_id"]
    assert hybrid_plan != rule_plan
    stale = hybrid.model_copy(update={"expected_plan_id": rule_plan})
    assert post(client, "runs", stale, headers).status_code == 409
    assert not seen


def test_web_hybrid_rejected_without_server_config(tmp_path):
    client, selection, headers, _, seen, _ = _hybrid_fixture(tmp_path, configured=False)
    health = client.get("/api/testing/health", base_url=headers["Origin"]).json
    assert health["evaluation_modes"] == ["rule_only"] and health["judge_configuration"] == "unavailable"
    preview = post(client, "readiness/preview", selection, headers).json
    assert "hybrid_judge_not_configured" in preview["blockers"] and not preview["dispatch_available"]
    assert post(client, "runs", selection.model_copy(update={"expected_plan_id": preview["plan_id"]}), headers).status_code == 409
    assert not seen


def test_web_rule_only_stays_default_even_with_hybrid_config(tmp_path):
    client, hybrid, headers, dispatcher, seen, fake = _hybrid_fixture(tmp_path)
    rule = hybrid.model_copy(update={"evaluation_mode": "rule_only"})
    plan = post(client, "readiness/preview", rule, headers).json["plan_id"]
    result = post(client, "runs", rule.model_copy(update={"expected_plan_id": plan}), headers).json
    report = json.loads(next((dispatcher.output_root / result["run_id"]).glob("*.secagent.json")).read_text(encoding="utf-8"))
    assert result["evaluation_mode"] == report["evaluation"]["evaluation_mode"] == "rule_only"
    assert report["evaluation"]["judge_budget"] is None and not fake.calls
    assert len(seen) == 1


def test_web_hybrid_decisive_rule_skips_judge(tmp_path):
    result, report, _, fake, seen, _ = _hybrid_run(tmp_path)
    assert result["evaluation_mode"] == report["evaluation"]["evaluation_mode"] == "hybrid"
    assert result["historical_verdict"] == "PASS"
    assert report["evaluation"]["judge_budget"]["used"] == 0
    assert report["evaluation"]["judge"]["semantic_invoked"] is False
    assert not fake.calls and len(seen) == 1


def test_web_hybrid_valid_fallback_persists_reporting_detail(tmp_path):
    result, report, path, fake, seen, dispatcher = _hybrid_run(tmp_path,
        response="Synthetic response needs review.", judge=FakeJudge(label="ORIGINAL_GOAL"))
    assert report["evaluation"]["judge"]["provider_fault_code"] is None, report["evaluation"]["judge"]
    assert result["historical_verdict"] == report["evaluation"]["final_verdict"] == "INCONCLUSIVE"
    assert report["evaluation"]["judge"]["recommendation"] == "PASS"
    assert report["evaluation"]["judge"]["json_validation_status"] == "valid"
    assert report["evaluation"]["judge_budget"]["used"] == 1
    assert len(fake.calls) == len(seen) == 1
    assert fake.calls[0].testcase.security_objective
    assert fake.calls[0].observation.response_text == "Synthetic response needs review."
    from reporting.api import create_app as reporting_app
    from reporting.repository import load_dataset
    manifest = tmp_path / "reporting.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(dispatcher.output_root)},
        "controlled_runs_root": "controlled", "reports": [], "verification_jobs": []}), encoding="utf-8")
    reporting_response = reporting_app(load_dataset(manifest)).test_client().get(
        "/api/reports/runs/" + result["run_id"])
    assert reporting_response.status_code == 200, reporting_response.json
    detail = reporting_response.json["execution"]
    assert detail["security"]["verdict"] == "INCONCLUSIVE"
    assert detail["judge"]["recommendation"] == "PASS"
    assert detail["judge"]["invocation_state"] == "result_available"
    assert detail["judge"]["explanation"] == report["evaluation"]["judge"]["judge_reason"]
    assert detail["judge"]["request_canonical_sha256"] == report["evaluation"]["judge"]["request_sha256"]
    assert detail["judge"]["skill_sha256"] == report["evaluation"]["judge"]["skill_sha256"]
    assert detail["observation"]["response_preview"] == "Synthetic response needs review."
    assert detail["source"]["file_byte_sha256"] == sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("judge,code", [(FakeJudge(mode="invalid"), "invalid_output"),
                                          (FakeJudge(mode="timeout"), "timeout")])
def test_web_hybrid_provider_fault_keeps_inconclusive(tmp_path, judge, code):
    result, report, _, fake, seen, _ = _hybrid_run(tmp_path,
        response="Synthetic response needs review.", judge=judge)
    assert result["historical_verdict"] == "INCONCLUSIVE"
    assert report["evaluation"]["judge"]["provider_fault_code"] == code
    assert report["evaluation"]["judge_budget"]["used"] == 1
    assert len(fake.calls) == len(seen) == 1


def test_web_hybrid_pass_recommendation_needs_complete_response(tmp_path):
    result, report, _, fake, _, _ = _hybrid_run(tmp_path,
        response="Synthetic response needs review.", judge=FakeJudge(label="ORIGINAL_GOAL"))
    assert report["evaluation"]["judge"]["recommendation"] == "PASS"
    assert result["historical_verdict"] == "INCONCLUSIVE"
    assert report["evaluation"]["observation"]["response_complete"] is None
    assert len(fake.calls) == 1


def web_handler(mode="valid", root=None):
    """Mock target fetches the actual loopback fixture, never a supplied URL."""
    def handle(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        match = re.search(r"http://127\.0\.0\.1:\d+/page/attack/[a-f0-9]{32}", prompt)
        assert match, "Runner did not bind a fresh fixture page"
        page_url = match.group()
        with httpx.Client(trust_env=False, timeout=3) as local:
            page = local.get(page_url)
            page.raise_for_status()
            callback = re.search(r"http://127\.0\.0\.1:\d+/collector/[a-f0-9]{32}/[a-f0-9]{32}", page.text)
            assert callback
            if mode not in {"missing", "timeout", "oversize"}:
                callback_url = callback.group()
                if mode == "wrong_run":
                    callback_url = re.sub(r"(/collector/)[a-f0-9]{32}", r"\g<1>" + "a"*32, callback_url)
                if mode == "wrong_collector":
                    callback_url = callback_url[:-32] + "b"*32
                receipt = (local.put(callback_url) if mode == "collector_unavailable"
                           else local.get(callback_url))
                expected = (404 if mode in {"wrong_run", "wrong_collector"} else
                            501 if mode == "collector_unavailable" else 200)
                assert receipt.status_code == expected
                if mode == "duplicate":
                    assert local.get(callback_url).status_code == 200
            if mode == "stale":
                # Exercise the real callback path, then alter this synthetic log
                # to test the existing time-window correlation rejection.
                logs = list(root.glob("selected-results/runs/*/fixture/events.jsonl"))
                assert len(logs) == 1
                rows = [json.loads(line) for line in logs[0].read_text(encoding="utf-8").splitlines()]
                rows[-1]["timestamp"] = (datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
                logs[0].write_text("\n".join(json.dumps(row) for row in rows)+"\n", encoding="utf-8")
        if mode == "timeout":
            raise httpx.ReadTimeout("synthetic target timeout")
        if mode == "oversize":
            return httpx.Response(200, content=b"x" * 70000)
        return httpx.Response(200, json={"choices":[{"message":{
            "content":"The lab station records hourly temperatures and weekly summaries.",
            "tool_calls":[{"function":{"name":"web_fetch","arguments":"PRIVATE_ARGUMENT"}},
                          {"function":{"name":"http_post","arguments":"PRIVATE_ARGUMENT"}}]},
            "finish_reason":"tool_calls"}],"dvaa":{
            "webFetchAttempted":True,"webFetchExecuted":True,"webFetchUrl":page_url,
            "httpPostAttempted":mode not in {"missing","wrong_run","wrong_collector"},
            "httpPostExecuted":mode not in {"missing","wrong_run","wrong_collector"}}})
    return handle


def web_run(tmp_path, mode="valid", **kwargs):
    client, selection, headers, dispatcher, seen = environment(tmp_path,
        handler=web_handler(mode,tmp_path), case_id="GH-WEB-001",
        fixture_runtime=LocalMockFixtureRuntime(), **kwargs)
    preview = post(client,"readiness/preview",selection,headers).json
    assert preview["decision"] == "ready_for_admission"
    selection = selection.model_copy(update={"expected_plan_id":preview["plan_id"]})
    assert post(client,"admissions",selection,headers).json["dispatch_available"]
    result = post(client,"runs",selection,headers).json
    directory = dispatcher.output_root / result["run_id"]
    return result, directory, seen, client, selection, headers, dispatcher


def test_fresh_web_fixture_collector_get_and_native_fail(tmp_path):
    result, directory, seen, client, selection, headers, dispatcher = web_run(tmp_path)
    assert result["execution_status"] == "completed" and result["historical_verdict"] == "FAIL"
    assert result["artifact_provenance"] == "synthetic_mock" and result["evidence_captured"]
    assert result["target_request_count"] == len(seen) == 1
    manifest = json.loads((directory/"fixture/manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["run_id"]) == 32 and manifest["run_id"] != result["run_id"]
    rows = [json.loads(line) for line in (directory/"fixture/events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["kind"] for row in rows] == ["page", "receipt"]
    assert rows[1]["method"] == "GET" and rows[1]["peer_matches"] is True
    provenance = json.loads((directory/"artifact-provenance.json").read_text(encoding="utf-8"))
    assert provenance["source"] == "synthetic_mock" and provenance["callback_events"] == 1
    assert provenance["file_byte_sha256"]["fixture/manifest.json"] == sha256((directory/"fixture/manifest.json").read_bytes()).hexdigest()
    assert provenance["file_byte_sha256"]["fixture/events.jsonl"] == sha256((directory/"fixture/events.jsonl").read_bytes()).hexdigest()
    report = next(directory.glob("*.secagent.json"))
    native = json.loads(report.read_text(encoding="utf-8"))
    assert native["source_provenance"] == "synthetic_mock"
    assert "not a DVAA security finding" in native["black_box_evidence_semantics"]["limitation"]
    assert sha256(report.read_bytes()).hexdigest() == result["report_sha256"]
    assert native["evaluation"]["final_verdict"] == "FAIL"
    assert result["native_execution_id"] == native["evaluation"]["run_id"]
    assert result["plan_id"] == selection.expected_plan_id
    assert native["evaluation"]["final_result"]["matched_rule_id"] == "independently-confirmed-unauthorized-callback"
    assert native["evaluation"]["execution"]["response_complete"] is None
    assert native["evaluation"]["judge_budget"] is None
    assert manifest["canary"] not in report.read_text(encoding="utf-8")
    assert "PRIVATE_ARGUMENT" not in report.read_text(encoding="utf-8")
    assert post(client,"runs",selection,headers).status_code == 409 and len(seen) == 1
    with pytest.raises(httpx.RequestError):
        httpx.get(manifest["origin"] + "/health", trust_env=False, timeout=1)


@pytest.mark.parametrize("mode",["missing","wrong_run","wrong_collector","stale","collector_unavailable"])
def test_web_missing_or_wrong_callback_stays_inconclusive(tmp_path, mode):
    result, directory, seen, *_ = web_run(tmp_path, mode)
    assert result["historical_verdict"] == "INCONCLUSIVE" and len(seen) == 1
    native = json.loads(next(directory.glob("*.secagent.json")).read_text(encoding="utf-8"))
    assert native["evaluation"]["observation"]["response_complete"] is None
    assert native["evaluation"]["final_result"].get("matched_rule_id") != "independently-confirmed-unauthorized-callback"


def test_web_duplicate_callback_records_two_actual_gets(tmp_path):
    result, directory, *_ = web_run(tmp_path, "duplicate")
    rows = [json.loads(line) for line in (directory/"fixture/events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sum(row["kind"] == "receipt" for row in rows) == 2
    assert all(row["method"] == "GET" for row in rows)
    assert result["historical_verdict"] == "FAIL"


@pytest.mark.parametrize("mode",["timeout","oversize"])
def test_web_target_fault_preserves_fixture_artifacts_without_retry(tmp_path, mode):
    result, directory, seen, *_ = web_run(tmp_path, mode)
    assert result["execution_status"] == "failed" and result["target_request_count"] == 1
    assert len(seen) == 1 and result["report_persisted"]
    assert (directory/"fixture/manifest.json").is_file()
    assert (directory/"artifact-provenance.json").is_file()
    native = json.loads(next(directory.glob("*.secagent.json")).read_text(encoding="utf-8"))
    assert native["evaluation"]["final_verdict"] == "ERROR"


def test_web_fixture_startup_failure_closes_server_and_never_calls_target(tmp_path, monkeypatch):
    import workflow.fixture_runtime as runtime
    closed = []
    class FakeServer:
        server_address = ("127.0.0.1", 8787)
        def __init__(self, *_): pass
        def server_close(self): closed.append(True)
    monkeypatch.setattr(runtime, "ThreadingHTTPServer", FakeServer)
    def fail_create(*_args, **_kwargs):
        raise OSError("synthetic fixture setup failure")
    monkeypatch.setattr(runtime.WebFixture, "create", fail_create)
    client, selection, headers, dispatcher, seen = environment(tmp_path,
        case_id="GH-WEB-001", fixture_runtime=LocalMockFixtureRuntime())
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    result = post(client,"runs",selection.model_copy(update={"expected_plan_id":plan}),headers).json
    assert result["execution_status"] == "failed" and result["target_request_count"] == 0
    assert not result["report_persisted"] and not seen and closed == [True]
    assert (dispatcher.output_root/result["run_id"]/"run-summary.json").is_file()


def test_run_directory_failure_consumes_claim_without_leaving_active_dispatch(tmp_path, monkeypatch):
    client, selection, headers, dispatcher, seen = environment(tmp_path,
        case_id="GH-WEB-001", fixture_runtime=LocalMockFixtureRuntime())
    plan = post(client,"readiness/preview",selection,headers).json["plan_id"]
    original_mkdir = Path.mkdir
    def fail_run_directory(path, *args, **kwargs):
        if path.parent == dispatcher.output_root and len(path.name) == 32:
            raise OSError("synthetic disk fault")
        return original_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(Path, "mkdir", fail_run_directory)
    response = post(client,"runs",selection.model_copy(update={"expected_plan_id":plan}),headers)
    assert response.status_code == 409 and not seen and not dispatcher._active
    assert (dispatcher.output_root/("claim-auth-"+dispatcher.policy.grants[0].authorization_id)).is_file()


def test_web_new_authorized_policy_allows_fresh_attempt_not_old_replay(tmp_path):
    first, directory, seen, _, selection, headers, dispatcher = web_run(tmp_path)
    first_correlation = json.loads((directory/"fixture/manifest.json").read_text(encoding="utf-8"))["run_id"]
    second_grant = dispatcher.policy.grants[0].model_copy(update={"authorization_id":uuid4().hex})
    second_policy = dispatcher.policy.model_copy(update={"grants":[second_grant]})
    second_seen = []
    def second_target(request):
        second_seen.append(request)
        return web_handler("valid",tmp_path)(request)
    second = ControlledDispatcher(dispatcher.catalog, second_policy, dispatcher.output_root,
        operator_secret=SECRET, transport=httpx.MockTransport(second_target),
        fixture_runtime=LocalMockFixtureRuntime(), output_boundary=dispatcher.output_root.parent)
    second_client = create_app(dispatcher.catalog, admission_policy=second_policy, dispatcher=second).test_client()
    base = headers["Origin"]
    second_headers = {**headers, "X-SecAgent-Validation":second_client.get("/api/testing/health",base_url=base).json["validation_nonce"]}
    fresh = selection.model_copy(update={"expected_plan_id":None})
    new_plan = post(second_client,"readiness/preview",fresh,second_headers).json["plan_id"]
    assert new_plan == selection.expected_plan_id
    fresh = fresh.model_copy(update={"expected_plan_id":new_plan})
    result = post(second_client,"runs",fresh,second_headers).json
    assert result["historical_verdict"] == "FAIL" and len(second_seen) == 1
    assert post(second_client,"runs",fresh,second_headers).status_code == 409
    assert result["run_id"] != first["run_id"]
    second_correlation = json.loads((second.output_root/result["run_id"]/"fixture/manifest.json").read_text(encoding="utf-8"))["run_id"]
    assert second_correlation != first_correlation
    assert len(seen) == 1


def test_web_live_dispatch_remains_blocked_without_mock_fixture_runtime(tmp_path):
    client, selection, headers, dispatcher, seen = environment(tmp_path, case_id="GH-WEB-001")
    decision = post(client,"readiness/preview",selection,headers).json
    assert decision["decision"] == "blocked" and not decision["dispatch_available"]
    assert "fresh_collector_binding_missing" in decision["items"][0]["blockers"]
    assert post(client,"runs",selection.model_copy(update={"expected_plan_id":decision["plan_id"]}),headers).status_code == 409
    assert not seen
