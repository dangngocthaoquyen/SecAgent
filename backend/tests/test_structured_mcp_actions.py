"""Offline contract checks for the separate, bounded MCP action workflow."""

import json
from pathlib import Path

import httpx
import pytest

from workflow.catalog import TargetCatalog
from workflow.mcp_actions import McpActionWorkflow, McpActionRejected, load_cases
from workflow.models import CatalogConfig, Preset


ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "configs" / "mcp_actions" / "dvaa_toolbot_canary.json"


def catalog(*, reviewed=True):
    preset = Preset(id="local-agent-7010", name="Local AI Agent", reviewed=reviewed,
        endpoint="http://127.0.0.1:7010/", protocol="mcp-jsonrpc",
        models=["mcp-service"], default_model="mcp-service", timeout_default=5)
    return TargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="research", targets=[preset]))


def service(tmp_path, *, reviewed=True, response_id=None, hybrid_config=None):
    calls = []

    def handler(request):
        body = json.loads(request.content)
        calls.append(body)
        assert body["method"] == "tools/call"
        assert body["params"] == {"name": "read_file", "arguments": {"path": "asi05-public-canary.txt"}}
        return httpx.Response(200, json={"jsonrpc": "2.0",
            "id": body["id"] if response_id is None else response_id,
            "result": {"content": [{"type": "text", "text": json.dumps({
                "success": True, "path": "asi05-public-canary.txt", "content": "dummy"})}]}})

    workflow = McpActionWorkflow(catalog(reviewed=reviewed), tmp_path, CASES,
        transport=httpx.MockTransport(handler), hybrid_config=hybrid_config)
    return workflow, calls


def run(workflow, **changes):
    row = {"case_id": "ASI05-DVAA-LAB-READ-001", "target_id": "local-agent-7010",
        "profile_revision": workflow.catalog._revisions["local-agent-7010"],
        "catalog_sha256": workflow.catalog_sha256, "authorization_confirmed": True}
    return workflow.run(**(row | changes))


def test_catalog_is_structured_and_policy_bound():
    case, = load_cases(CASES)
    assert case.tool_name == "read_file"
    assert case.execution_policy.review_status == "draft"
    assert case.attribution == "tool_service/direct_request"


@pytest.mark.parametrize("changes", [
    {"authorization_confirmed": False}, {"target_id": "other"},
    {"profile_revision": "0" * 64}, {"catalog_sha256": "0" * 64},
    {"evidence_configuration": "configured_adapter"},
])
def test_admission_rejects_before_target_request(tmp_path, changes):
    workflow, calls = service(tmp_path)
    with pytest.raises(McpActionRejected):
        run(workflow, **changes)
    assert calls == []


def test_unreviewed_target_rejected_before_request(tmp_path):
    workflow, calls = service(tmp_path, reviewed=False)
    with pytest.raises(McpActionRejected, match="mcp_target_not_reviewed_or_stale"):
        run(workflow)
    assert calls == []


def test_one_live_mcp_request_runs_execution_gate_without_pi(tmp_path):
    workflow, calls = service(tmp_path)
    result = run(workflow)
    assert len(calls) == result["target_request_count"] == 1
    assert result["final_verdict"] == "INCONCLUSIVE"
    assert result["semantic_invoked"] is False
    report = json.loads(Path(result["report_path"]).read_text(encoding="utf-8"))
    from reporting.repository import load_dataset, load_mcp_run
    manifest = tmp_path / 'mcp-report-selection.json'
    manifest.write_text(json.dumps({'dataset_schema_version':'1.0.0',
        'allowed_roots':{'controlled':str(workflow.output_root)},
        'controlled_runs_root':'controlled','reports':[]}), encoding='utf-8')
    dataset = load_dataset(manifest)
    assert load_mcp_run(dataset, result['execution_id'])[0]['testcase_id'] == result['testcase_id']
    from reporting.api import create_app as reporting_app
    reporting = reporting_app(dataset).test_client()
    history = reporting.get('/api/reports/saved-runs').get_json()
    assert history['total'] == 1 and history['items'][0]['kind'] == 'mcp_action'
    detail = reporting.get('/api/reports/mcp-runs/' + result['execution_id'])
    assert detail.status_code == 200 and detail.get_json()['native_report']['final_verdict'] == 'INCONCLUSIVE'
    assert report["evaluation_scope"] == "execution_action"
    assert report["execution_evaluation"]["evidence_level"] == "tool_invocation"
    assert report["execution_evaluation"]["attribution"] == "direct_request"
    assert report["execution_evaluation"]["trace_completeness"] == "partial"
    assert report["judge"]["semantic_invoked"] is False
    assert report["observation"]["response_text"] == "[REDACTED_MCP_TOOL_RESULT]"
    assert len(report["observation"]["response_sha256"]) == 64
    assert any(event["kind"] == "tool_request" for event in report["observation"]["evidence"])


def test_wrong_json_rpc_response_id_cannot_become_pass(tmp_path):
    workflow, calls = service(tmp_path, response_id="wrong")
    result = run(workflow)
    assert len(calls) == 1
    assert result["final_verdict"] != "PASS"
    assert result["semantic_invoked"] is False


def test_shared_pi_configuration_stays_gated_for_draft_action_scope(tmp_path, monkeypatch):
    from integrations.external_evaluator.pi import PiEvaluatorConfig, PiEvaluatorProvider
    from testing import RunnerEvaluationConfig

    monkeypatch.setattr(PiEvaluatorProvider, "evaluate", lambda *_: pytest.fail("Pi must not be called"))
    config = RunnerEvaluationConfig(mode="hybrid", judge_enabled=True,
        allow_live_judge=True, max_judge_calls=1,
        pi=PiEvaluatorConfig(executable="pi", provider="fake", model="fake-model",
            timeout_seconds=1, credential_env=("FAKE_JUDGE_KEY",)))
    workflow, calls = service(tmp_path, hybrid_config=config)
    result = run(workflow, evaluation_mode="hybrid")
    assert len(calls) == 1
    assert result["semantic_invoked"] is False
    assert result["final_verdict"] == "INCONCLUSIVE"


def test_reviewed_policy_requires_separate_catalog_pin(tmp_path):
    row = json.loads(CASES.read_text(encoding="utf-8"))
    policy = row["cases"][0]["execution_policy"]
    policy["review_status"] = "reviewed"
    policy.pop("revision_sha256")
    from hashlib import sha256
    policy["revision_sha256"] = sha256(json.dumps(policy, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    path = tmp_path / "reviewed.json"
    path.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(McpActionRejected, match="reviewed_mcp_catalog_pin_required"):
        McpActionWorkflow(catalog(), tmp_path, path)


def test_mcp_api_requires_operator_authentication_and_nonce(tmp_path):
    from threading import RLock
    from types import SimpleNamespace
    from workflow.api import create_app
    from workflow.management import ManagedTargetCatalog

    seed = catalog()._config
    managed = ManagedTargetCatalog(seed, tmp_path / "managed", local_single_user=True)
    service = McpActionWorkflow(managed, tmp_path / "runs", CASES)
    dispatcher = SimpleNamespace(catalog=managed, _lock=RLock(), _active=False,
        authorized=lambda secret: secret == "operator-test-only")
    app = create_app(managed, port=8092, dispatcher=dispatcher,
        mcp_action_service=service, local_single_user=True)
    client = app.test_client()
    base = "http://127.0.0.1:8092"
    denied = client.get("/api/testing/mcp-actions", base_url=base)
    assert denied.status_code == 403
    listed = client.get("/api/testing/mcp-actions", base_url=base,
        headers={"X-SecAgent-Operator": "operator-test-only"})
    assert listed.status_code == 200
    assert listed.json["cases"][0]["testcase_id"] == "ASI05-DVAA-LAB-READ-001"
    attempt = client.post("/api/testing/mcp-actions/run", base_url=base,
        headers={"Origin": base, "Content-Type": "application/json",
                 "X-SecAgent-Operator": "operator-test-only"},
        json={"testcase_id": "ASI05-DVAA-LAB-READ-001"})
    assert attempt.status_code == 403
    assert list((tmp_path / "runs").glob("mcp-action-*")) == []
