"""Offline contract checks for a pinned Promptfoo Agent provider HTTP facade."""

import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import zipfile
from hashlib import sha256

import pytest

from targets.adapters.http_evidence import reported_http_evidence
from targets.bridges.promptfoo_http import (load_config, make_handler,
    prepare_provider, provider_response)


FAKE_PROVIDER = b"""
module.exports = class FakeAgent {
  async callApi(prompt) {
    const rpc = await fetch(process.env.MOCK_MCP_URL, {method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',
        params:{name:'read_file',arguments:{path:'canary.txt'}}})});
    const mcpResponse = await rpc.json();
    return {output:'Assistant response to '+prompt,
      metadata:{toolCalls:[{name:'read_file',args:{path:'canary.txt'},
        invoked:true,mcpResponse}]}};
  }
};
"""


def _config(tmp_path, source=FAKE_PROVIDER):
    archive = tmp_path / "provider.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("lab/provider.cjs", source)
    path = tmp_path / "bridge.json"
    path.write_text(json.dumps({"schema_version": "1.0.0", "provider_zip": str(archive),
        "provider_entry": "lab/provider.cjs", "provider_sha256": sha256(source).hexdigest(),
        "model": "deepseek-chat", "credential_env": "DEEPSEEK_API_KEY",
        "port": 7019, "category": "ASI05"}), encoding="utf-8")
    return path


def test_provider_pin_and_storage_reject_changes(tmp_path):
    path = _config(tmp_path)
    config = load_config(path)
    provider = prepare_provider(config, tmp_path / "private")
    assert sha256(provider.read_bytes()).hexdigest() == config["provider_sha256"]
    provider.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="agent_bridge_storage_invalid"):
        prepare_provider(config, tmp_path / "private")
    value = json.loads(path.read_text(encoding="utf-8"))
    value["provider_sha256"] = "0" * 64
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="agent_bridge_config_invalid"):
        load_config(path)


def test_mock_agent_to_mcp_keeps_reported_provenance_and_secret_out(tmp_path, monkeypatch):
    calls = []

    class MockMcp(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(body)
            raw = json.dumps({"jsonrpc": "2.0", "id": 1,
                "result": {"content": [{"type": "text", "text": "synthetic canary"}]}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), MockMcp)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        monkeypatch.setenv("DEEPSEEK_API_KEY", "SECRET_SENTINEL_DO_NOT_EXPORT")
        monkeypatch.setenv("MOCK_MCP_URL", f"http://127.0.0.1:{server.server_port}/")
        config = load_config(_config(tmp_path))
        provider = prepare_provider(config, tmp_path / "private")
        status, response = provider_response(provider, config, "one synthetic prompt")
        assert status == 200
        assert response["choices"][0]["message"]["content"] == "Assistant response to one synthetic prompt"
        assert len(calls) == 1 and calls[0]["method"] == "tools/call"
        assert calls[0]["params"] == {"name": "read_file", "arguments": {"path": "canary.txt"}}
        trace = response["secagent_bridge"]
        assert trace["trace_completeness"] == "partial" and trace["execution_verified"] is False
        assert trace["tool_calls"][0]["invoked"] is True
        evidence = reported_http_evidence(response)
        call = next(x for x in evidence if x["kind"] == "agent_bridge_tool_call")
        assert call["data"]["mcp_request_dispatched_reported"] is True
        assert call["data"]["execution_verified"] is False
        assert "SECRET_SENTINEL_DO_NOT_EXPORT" not in json.dumps(response)
        assert "SECRET_SENTINEL_DO_NOT_EXPORT" not in json.dumps(evidence)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_bridge_rejects_invalid_body_without_provider_call(tmp_path):
    config = load_config(_config(tmp_path))
    invoked = []
    handler = make_handler(config, tmp_path / "provider.cjs",
        invoke=lambda *_: invoked.append(True) or (200, {}))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    import urllib.request
    import urllib.error
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=json.dumps({"model": "wrong", "messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=2)
        assert exc.value.code == 400
        assert invoked == []
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_bridge_accepts_secagent_chat_connection_probe(tmp_path):
    config = load_config(_config(tmp_path))
    prompts = []
    handler = make_handler(config, tmp_path / "provider.cjs",
        invoke=lambda _path, _config, prompt: (prompts.append(prompt) or (200, {
            "choices": [{"message": {"content": "ready"}, "finish_reason": "stop"}]})))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/v1/models", timeout=2) as response:
            assert json.load(response)["data"][0]["id"] == "deepseek-chat"
        assert prompts == []  # Metadata discovery never invokes the provider.
        body = {"model": "deepseek-chat", "messages": [{"role": "user",
            "content": "Reply with one word: ready."}], "stream": False}
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
            assert json.load(response)["choices"][0]["message"]["content"] == "ready"
        assert prompts == ["Reply with one word: ready."]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_provider_fault_does_not_echo_secret(tmp_path, monkeypatch):
    source = b"module.exports=class X{async callApi(){throw Error(process.env.DEEPSEEK_API_KEY)}}"
    config = load_config(_config(tmp_path, source))
    provider = prepare_provider(config, tmp_path / "private")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "SECRET_SENTINEL_DO_NOT_EXPORT")
    status, response = provider_response(provider, config, "benign")
    assert status == 502 and response == {"error": {"code": "provider_failed"}}
    assert "SECRET_SENTINEL_DO_NOT_EXPORT" not in json.dumps(response)


def test_local_toolbot_30_one_case_preview_is_agent_chat_only(tmp_path, monkeypatch):
    """Use the real imported bytes when available; all network calls are mocked."""
    source = Path(r"E:\KiemLaiSS1\testcases_dvaa_toolbot_asi05.json")
    if not source.is_file():
        pytest.skip("Local Promptfoo ToolBot dataset is unavailable")
    import socket
    import httpx
    from workflow.admission import AdmissionPolicy
    from workflow.api import create_app
    from workflow.asi05_policy import ASI05PolicyDraft
    from workflow.dataset_normalizer import normalize_dataset
    from workflow.dataset_repository import DatasetRepository
    from workflow.dispatch import ControlledDispatcher
    from workflow.generic_imported_batch import GenericImportedBatchWorkflow
    from workflow.management import ManagedProfile, ManagedTargetCatalog, ReviewProfile, SaveProfile
    from workflow.models import CatalogConfig
    from testing.evaluation_config import RunnerEvaluationConfig
    from integrations.external_evaluator.pi import PiEvaluatorConfig

    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Network forbidden"))
    requests = []
    def mock_agent(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"},
                                                "finish_reason": "stop"}]})
    transport = httpx.MockTransport(mock_agent)
    catalog = ManagedTargetCatalog(CatalogConfig(catalog_schema_version="1.0.0",
        policy_ref="offline-agent-bridge-test", targets=[]), tmp_path / "operator",
        probe_transport=transport, local_single_user=True)
    row = catalog.save_profile(SaveProfile(profile=ManagedProfile(
        id="toolbot-agent-bridge", name="ToolBot Agent bridge", platform_id="lab",
        platform_name="Lab", endpoint="http://127.0.0.1:7019/v1/chat/completions",
        protocol="openai-chat", model="deepseek-chat", timeout_seconds=3)))
    row = catalog.review_profile(ReviewProfile(target_id=row["id"],
        profile_revision=row["profile_revision"], policy_ref=row["policy_ref"],
        endpoint=row["endpoint"], protocol=row["protocol"],
        model=row["default_model"], capabilities=["chat"], authorization_confirmed=True))
    repo = DatasetRepository(catalog.data_dir)
    dataset, _ = repo.save_dataset(normalize_dataset(source.read_bytes(), source.name))
    assert dataset.file_sha256 == "054112a0f8b9ae7adc3893b04a56d3173fb7ecd855b8d150008bdfa4ad24bb8b"
    assert len(dataset.testcases) == 30
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), tmp_path / "runs",
        operator_secret="x" * 40, output_boundary=tmp_path,
        hybrid_config=RunnerEvaluationConfig(mode="hybrid", judge_enabled=True,
            allow_live_judge=True, max_judge_calls=1,
            pi=PiEvaluatorConfig(executable="never-invoked", provider="test",
                model="test", timeout_seconds=1)))
    workflow = GenericImportedBatchWorkflow(dispatcher, repo, execution_mode="both",
        mock_live_transport=transport)
    policy = workflow.asi05_policies.create(ASI05PolicyDraft(target_id=row["id"],
        prohibited_command_behavior="Unauthorized command artifact",
        allowed_benign_context="Authorized project inspection",
        expected_response_boundary="No prohibited command artifact"))
    workflow.asi05_policies.review(policy["policy_id"], policy["revision_sha256"], confirmed=True)
    app = create_app(catalog, dispatcher=dispatcher, operator_secret="x" * 40,
        local_single_user=True, batch_service=workflow, dataset_repository=repo)
    client = app.test_client()
    base = "http://127.0.0.1:8092"
    nonce = client.get("/api/testing/health", base_url=base).json["validation_nonce"]
    headers = {"Origin": base, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": "x" * 40}
    case = dataset.testcases[0]
    draft = {key: row[key] for key in ("profile_revision", "policy_ref", "endpoint",
        "protocol", "method", "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model="deepseek-chat", timeout_seconds=3)
    selection = {"workflow_id": "imported", "target": draft,
        "dataset_id": dataset.dataset_id, "testcase_ids": [case.internal_id],
        "total_request_budget": 1, "transport_mode": "live_local_http",
        "evaluation_mode": "hybrid", "asi_category": "ASI05"}
    before = client.post("/api/testing/batches/preview", base_url=base,
        json=selection, headers=headers).json
    assert before["ready_count"] == 0
    assert before["items"][0]["reason"] == "imported_live_connection_check_required"
    assert requests == []
    checked = client.post("/api/testing/connection-checks", base_url=base,
        json={"target_id": row["id"], "profile_revision": row["profile_revision"],
              "policy_ref": row["policy_ref"]}, headers=headers)
    assert checked.status_code == 200 and checked.json["connection_status"] == "succeeded"
    assert len(requests) == 1
    assert json.loads(requests[0].content)["messages"][0]["content"] == "Reply with one word: ready."
    preview = client.post("/api/testing/batches/preview", base_url=base,
        json=selection, headers=headers).json
    assert preview["ready_count"] == preview["total"] == 1
    assert preview["target_request_budget"] == 1
    assert preview["items"][0]["input_sha256"] == case.prompt_sha256
    assert preview["items"][0]["evaluation_readiness"] == "reviewed_asi05_response_semantic"
    assert preview["items"][0]["asi_category"] == "ASI05"
    assert len(requests) == 1  # Preview itself never calls the target or Judge.
