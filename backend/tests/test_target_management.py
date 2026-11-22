"""Operator-managed catalog and benign probe, with no real target I/O."""
import json
import socket
from threading import Event, Thread
from types import SimpleNamespace
from pathlib import Path

import httpx
import pytest

from workflow.api import create_app
from workflow.admission import AdmissionPolicy
from workflow.dispatch import ControlledDispatcher
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "operator-only-test-secret-" + "x" * 32


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def setup(tmp_path, *, transport=None, seed=None):
    raw = seed or {"catalog_schema_version": "1.0.0", "policy_ref": "managed-lab-v1",
                   "credential_aliases": {}, "targets": []}
    catalog = ManagedTargetCatalog(CatalogConfig.model_validate(raw), tmp_path / "operator-data",
                                   probe_transport=transport)
    client = create_app(catalog, operator_secret=SECRET).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    return catalog, client, headers


def profile(**changes):
    row = {"id": "dvaa-researchbot", "name": "DVAA ResearchBot", "platform_id": "dvaa",
           "platform_name": "DVAA", "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
           "protocol": "openai-chat", "model": "researchbot", "timeout_seconds": 30}
    return row | changes


def post(client, route, body, headers):
    return client.post("/api/testing/" + route, base_url=BASE, json=body, headers=headers)


def test_create_review_edit_restart_and_stale_revision(tmp_path):
    catalog, client, headers = setup(tmp_path)
    assert client.get("/api/testing/health", base_url=BASE).json["target_management_enabled"]
    initial = {"profile": profile()}
    assert post(client, "managed-targets/validate", initial, headers).status_code == 200
    created = post(client, "managed-targets/create", initial, headers)
    assert created.status_code == 200
    row = created.json["profile"]
    assert row["authorization_status"] == "review_required"
    assert row["connection_probe"]["status"] == "unsupported"
    assert post(client, "managed-targets/create", initial, headers).status_code == 409
    assert post(client, "target-drafts/validate", {
        "target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "method": "POST", "model": row["default_model"],
        "request_mapping": row["request_mapping"], "response_parser": row["response_parser"],
        "timeout_seconds": 30, "credential_alias": None}, headers).json["errors"] == ["operator_review_required"]
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
              "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
              "protocol": row["protocol"], "model": row["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review | {"authorization_confirmed": False}, headers).status_code == 400
    approved = post(client, "managed-targets/review", review, headers)
    assert approved.status_code == 200
    assert approved.json["profile"]["profile_revision"] == row["profile_revision"]
    assert approved.json["profile"]["authorization_status"] == "reviewed_for_offline_configuration"
    reloaded, _, _ = setup(tmp_path)
    assert reloaded.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"
    changed = {"profile": profile(endpoint="http://127.0.0.1:7016/v1/chat/completions"),
               "expected_profile_revision": row["profile_revision"]}
    updated = post(client, "managed-targets/update", changed, headers)
    assert updated.status_code == 200
    new = updated.json["profile"]
    assert new["profile_revision"] != row["profile_revision"]
    assert new["authorization_status"] == "review_required"
    assert post(client, "managed-targets/review", review, headers).status_code == 409
    assert post(client, "managed-targets/update", changed, headers).status_code == 409
    restarted, _, _ = setup(tmp_path)
    assert restarted.public_targets()[0]["endpoint"] == new["endpoint"]
    assert restarted.public_targets()[0]["authorization_status"] == "review_required"
    assert json.loads((tmp_path / "operator-data" / "target-catalog.json").read_text())["reviews"] == []


def test_name_only_update_preserves_review_and_connection_binding(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    catalog, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    created = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    review = {"target_id": created["id"], "profile_revision": created["profile_revision"],
              "policy_ref": created["policy_ref"], "endpoint": created["endpoint"],
              "protocol": created["protocol"], "model": created["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    check = {"target_id": created["id"], "profile_revision": created["profile_revision"],
             "policy_ref": created["policy_ref"]}
    assert post(client, "connection-checks", check, headers).json["connection_status"] == "succeeded"
    renamed = post(client, "managed-targets/update", {"profile": profile(name="Named ResearchBot"),
        "expected_profile_revision": created["profile_revision"]}, headers)
    assert renamed.status_code == 200
    target = renamed.json["profile"]
    assert target["name"] == "Named ResearchBot"
    assert target["profile_revision"] == created["profile_revision"]
    assert target["authorization_status"] == "reviewed_for_offline_configuration"
    assert post(client, "connection-checks", check, headers).json["connection_status"] == "succeeded"
    assert len(seen) == 2
    restarted, _, _ = setup(tmp_path)
    assert restarted.public_targets()[0]["name"] == "Named ResearchBot"
    assert restarted.public_targets()[0]["profile_revision"] == created["profile_revision"]
    assert restarted.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"


def test_operator_platform_reassignment_preserves_identity_review_and_protocol(tmp_path):
    _, client, headers = setup(tmp_path)
    codebot = post(client, "managed-targets/create", {"profile": profile(
        id="local-agent-7004", name="DVAA CodeBot", platform_id="local-http",
        platform_name="Local HTTP", endpoint="http://127.0.0.1:7004/v1/chat/completions",
        model="default")}, headers).json["profile"]
    toolbot = post(client, "managed-targets/create", {"profile": profile(
        id="local-agent-7010", name="DVAA ToolBot", platform_id="local-agent",
        platform_name="Local Agent", endpoint="http://127.0.0.1:7010/",
        protocol="mcp-jsonrpc", model="mcp-service")}, headers).json["profile"]
    review = {"target_id": codebot["id"], "profile_revision": codebot["profile_revision"],
              "policy_ref": codebot["policy_ref"], "endpoint": codebot["endpoint"],
              "protocol": codebot["protocol"], "model": codebot["default_model"],
              "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    revised = profile(id=codebot["id"], name="DVAA CodeBot", platform_id="dvaa",
        platform_name="DVAA", endpoint=codebot["endpoint"], model="default")
    request = {"profile": revised, "expected_profile_revision": codebot["profile_revision"]}
    assert post(client, "managed-targets/update", request, headers).status_code == 409
    changed = post(client, "managed-targets/update",
        request | {"platform_change_confirmed": True}, headers)
    assert changed.status_code == 200
    assert changed.json["profile"]["profile_revision"] == codebot["profile_revision"]
    assert changed.json["profile"]["authorization_status"] == "reviewed_for_offline_configuration"
    assert changed.json["profile"]["platform_provenance"] == "operator_declared"
    other = profile(id=toolbot["id"], name="DVAA ToolBot", platform_id="dvaa",
        platform_name="DVAA", endpoint=toolbot["endpoint"], protocol="mcp-jsonrpc",
        model="mcp-service")
    assert post(client, "managed-targets/update", {"profile": other,
        "expected_profile_revision": toolbot["profile_revision"],
        "platform_change_confirmed": True}, headers).status_code == 200
    rows = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    assert {row["platform_id"] for row in rows} == {"dvaa"}
    assert {row["protocol"] for row in rows} == {"openai-chat", "mcp-jsonrpc"}


def test_archive_selected_is_atomic_and_blocks_new_use_without_deleting_reports(tmp_path):
    catalog, client, headers = setup(tmp_path)
    rows = [post(client, "managed-targets/create", {"profile": profile(
        id=f"target-{i}", name=f"Target {i}",
        endpoint=f"http://127.0.0.1:{7010+i}/v1/chat/completions")}, headers).json["profile"]
        for i in range(3)]
    history = tmp_path / "native_report.json"
    history.write_text('{"target_id":"target-0","final_verdict":"INCONCLUSIVE"}')
    selection = [{"target_id": rows[i]["id"], "profile_revision": rows[i]["profile_revision"]}
                 for i in (0, 2)]
    assert post(client, "managed-targets/archive", {"targets": selection,
        "archive_confirmed": True}, {k: v for k, v in headers.items()
            if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "managed-targets/archive", {"targets": selection,
        "archive_confirmed": False}, headers).status_code == 409
    bad = [selection[0], selection[1] | {"profile_revision": "0" * 64}]
    assert post(client, "managed-targets/archive", {"targets": bad,
        "archive_confirmed": True}, headers).status_code == 409
    assert len(catalog.public_targets()) == 3
    archived = post(client, "managed-targets/archive", {"targets": selection,
        "archive_confirmed": True}, headers)
    assert archived.status_code == 200
    assert {row["id"] for row in catalog.public_targets()} == {"target-1"}
    assert {row["id"] for row in archived.json["archived"]} == {"target-0", "target-2"}
    assert history.read_text() == '{"target_id":"target-0","final_verdict":"INCONCLUSIVE"}'
    assert post(client, "managed-targets/update", {"profile": profile(id="target-0",
        name="Changed", endpoint=rows[0]["endpoint"]),
        "expected_profile_revision": rows[0]["profile_revision"]}, headers).status_code == 409
    restarted, _, _ = setup(tmp_path)
    assert [row["id"] for row in restarted.public_targets()] == ["target-1"]
    assert len(restarted.archived_targets()) == 2
    assert post(client, "managed-targets/restore", {"target_id": "target-0",
        "profile_revision": rows[0]["profile_revision"],
        "restore_confirmed": True}, headers).status_code == 200
    assert {row["id"] for row in catalog.public_targets()} == {"target-0", "target-1"}


def test_duplicate_endpoint_rejected_without_rewriting_existing_target(tmp_path):
    _, client, headers = setup(tmp_path)
    original = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    duplicate = profile(id="another-name", name="Another name")
    assert post(client, "managed-targets/create", {"profile": duplicate}, headers).status_code == 409
    rows = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    assert [row["id"] for row in rows] == [original["id"]]


@pytest.mark.parametrize("bad", [
    "http://169.254.169.254/latest/meta-data", "http://example.com/chat",
    "http://user:secret@127.0.0.1/chat", "http://127.0.0.1/chat?token=secret",
    "file:///tmp/local", "http://127.0.0.1:7015/a/../chat",
])
def test_invalid_endpoint_rejected_before_persistence(tmp_path, bad):
    _, client, headers = setup(tmp_path)
    response = post(client, "managed-targets/create", {"profile": profile(endpoint=bad)}, headers)
    assert response.status_code in {400, 409}
    assert not (tmp_path / "operator-data" / "target-catalog.json").exists()
    assert "secret" not in response.get_data(as_text=True)


def test_admin_requires_operator_auth_origin_and_csrf(tmp_path):
    _, client, headers = setup(tmp_path)
    body = {"profile": profile()}
    for altered in ({k: v for k, v in headers.items() if k != "X-SecAgent-Operator"},
                    headers | {"X-SecAgent-Operator": "wrong"},
                    {k: v for k, v in headers.items() if k != "X-SecAgent-Validation"},
                    headers | {"Origin": "https://evil.example"}):
        assert post(client, "managed-targets/create", body, altered).status_code == 403
    assert client.get("/api/testing/managed-targets", base_url=BASE).status_code == 403
    assert post(client, "managed-targets/create", body, headers).status_code == 200
    assert SECRET not in client.get("/api/testing/targets", base_url=BASE).get_data(as_text=True)


def test_reviewed_exact_endpoint_probe_is_bounded_and_response_contract_checked(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    catalog, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert not seen
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    probe = post(client, "connection-checks", selection, headers)
    assert probe.status_code == 200
    assert probe.json["connection_status"] == "succeeded"
    assert probe.json["connection_reachable"] is True
    assert probe.json["runtime_protocol_compatible"] is True
    assert probe.json["target_request_count"] == len(seen) == 1
    assert probe.json["security_test_executed"] is False
    assert str(seen[0].url) == row["endpoint"] and seen[0].method == "POST"
    assert "tools" not in json.loads(seen[0].content)
    assert json.loads(seen[0].content)["model"] == "researchbot"
    assert "ready" not in json.dumps(probe.json)
    assert catalog.public_targets()[0]["connection_probe"]["status"] == "supported"


def test_generic_mcp_profile_review_and_tools_list_probe_only(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        assert json.loads(request.content)["method"] == "tools/list"
        return httpx.Response(200, json={"jsonrpc": "2.0",
            "id": "secagent-connection-check", "result": {"tools": [{"name": "read_file"}]}})
    _, client, headers = setup(tmp_path, transport=httpx.MockTransport(reply))
    candidate = profile(id="generic-mcp", name="Generic MCP", platform_id="local-agent",
        platform_name="Local Agent", protocol="mcp-jsonrpc", endpoint="http://127.0.0.1:7010/",
        model="mcp-service")
    created = post(client, "managed-targets/create", {"profile": candidate}, headers)
    assert created.status_code == 200
    row = created.json["profile"]
    assert row["authorization_status"] == "review_required"
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert not seen
    review = selection | {"endpoint": row["endpoint"], "protocol": row["protocol"],
        "model": row["default_model"], "capabilities": ["tool_call"],
        "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    probe = post(client, "connection-checks", selection, headers)
    assert probe.status_code == 200
    assert probe.json["connection_status"] == "succeeded"
    assert probe.json["reason"] == "mcp_tools_list_response"
    assert probe.json["target_request_count"] == len(seen) == 1
    assert probe.json["security_test_executed"] is False


def test_probe_rejects_redirect_and_stale_scope_without_second_request(tmp_path):
    seen = []
    transport = httpx.MockTransport(lambda request: (seen.append(request), httpx.Response(302,
        headers={"Location": "http://169.254.169.254/latest/meta-data"}))[1])
    _, client, headers = setup(tmp_path, transport=transport)
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    result = post(client, "connection-checks", selection, headers).json
    assert result["connection_status"] == "incompatible" and result["target_request_count"] == 1
    assert len(seen) == 1
    assert post(client, "connection-checks", selection | {"profile_revision": "f" * 64}, headers).status_code == 409
    assert len(seen) == 1


def test_frontend_grant_path_keeps_startup_dispatch_and_one_use_boundaries(tmp_path):
    catalog, _, _ = setup(tmp_path)
    output = tmp_path / "selected-results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), output / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(lambda _: pytest.fail("No target request")),
        output_boundary=output)
    client = create_app(catalog, dispatcher=dispatcher, operator_secret=SECRET).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"],
        "capabilities": ["chat"], "authorization_confirmed": True}
    post(client, "managed-targets/review", review, headers)
    draft = {k: row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol", "method",
                                  "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=30)
    selection = {"target": draft, "asi_categories": ["ASI01"], "testcase_ids": ["GH-C01"],
                 "target_request_budget": 1, "evaluation_mode": "rule_only"}
    before = post(client, "readiness/preview", selection, headers).json
    assert before["decision"] == "blocked"
    assert before["items"][0]["blockers"] == ["execution_authorization_missing_or_expired"]
    request = selection | {"expected_plan_id": before["plan_id"], "authorization_confirmed": True}
    assert post(client, "execution-grants", request,
        {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "execution-grants", request | {"expected_plan_id": "a" * 64}, headers).status_code == 409
    assert post(client, "execution-grants", request | {"testcase_ids": ["GH-001"]}, headers).status_code == 409
    issued = post(client, "execution-grants", request, headers)
    assert issued.status_code == 200
    assert issued.json["target_request_budget"] == 1
    assert len(list(dispatcher.output_root.glob("operator-grant-*.json"))) == 1
    after = post(client, "readiness/preview", selection, headers).json
    assert after["decision"] == "ready_for_admission" and after["plan_id"] == before["plan_id"]
    assert post(client, "execution-grants", request, headers).status_code == 409
    assert post(client, "runs", selection | {"expected_plan_id": "a" * 64}, headers).status_code == 409
    revised = post(client, "managed-targets/update", {"profile": profile(
        endpoint="http://127.0.0.1:7016/v1/chat/completions"),
        "expected_profile_revision": row["profile_revision"]}, headers).json["profile"]
    assert revised["authorization_status"] == "review_required"
    assert post(client, "readiness/preview", selection, headers).json["decision"] == "blocked"
    assert len(list(dispatcher.output_root.glob("claim-*.json"))) == 0


def test_grant_api_disabled_without_startup_controlled_runs(tmp_path):
    _, client, headers = setup(tmp_path)
    assert post(client, "execution-grants", {}, headers).status_code == 403


@pytest.mark.parametrize("extra", [
    {"reviewed": True}, {"credential_alias": "SECRET_ENV"},
    {"headers": {"Authorization": "private"}}, {"tools": ["shell"]},
    {"output_path": "C:/private/report.json"},
])
def test_profile_save_cannot_supply_reviews_credentials_or_paths(tmp_path, extra):
    _, client, headers = setup(tmp_path)
    assert post(client, "managed-targets/create", {"profile": profile(**extra)}, headers).status_code == 400
    assert not (tmp_path / "operator-data" / "target-catalog.json").exists()


def test_atomic_write_failure_leaves_previous_profile_and_review_unchanged(tmp_path, monkeypatch):
    catalog, client, headers = setup(tmp_path)
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    before = catalog.state_file.read_bytes()
    monkeypatch.setattr("workflow.management.os.replace", lambda *_: (_ for _ in ()).throw(OSError("disk fault")))
    response = post(client, "managed-targets/update", {"profile": profile(name="Changed name"),
        "expected_profile_revision": row["profile_revision"]}, headers)
    assert response.status_code == 409
    assert catalog.state_file.read_bytes() == before
    assert catalog.public_targets()[0]["name"] == row["name"]
    assert list(catalog.data_dir.glob(".target-catalog-*.tmp")) == []


def test_oversize_probe_response_is_unknown_and_never_echoed(tmp_path):
    seen = []
    def oversized(request):
        seen.append(request)
        return httpx.Response(200, content=b"PRIVATE_RESPONSE" * 2000)
    _, client, headers = setup(tmp_path, transport=httpx.MockTransport(oversized))
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    post(client, "managed-targets/review", selection | {"endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"], "capabilities": ["chat"],
        "authorization_confirmed": True}, headers)
    response = post(client, "connection-checks", selection, headers)
    assert response.json["connection_status"] == "unavailable"
    assert response.json["target_request_count"] == len(seen) == 1
    assert response.json["connection_reachable"] is None
    assert "PRIVATE_RESPONSE" not in response.get_data(as_text=True)


def test_managed_cli_starts_with_deny_all_policy_without_manual_grant_json(tmp_path, monkeypatch):
    from workflow import api
    captured = {}
    class FakeDispatcher:
        def __init__(self, catalog, policy, output_root, **kwargs):
            captured.update(catalog=catalog, policy=policy, output_root=output_root)
    monkeypatch.setenv("SECAGENT_WORKFLOW_OPERATOR_TOKEN", SECRET)
    monkeypatch.setattr(api, "ControlledDispatcher", FakeDispatcher)
    monkeypatch.setattr(api, "create_app", lambda *args, **kwargs: SimpleNamespace(run=lambda **_: None))
    seed = Path(__file__).resolve().parents[2] / "configs/workflow/authorized-targets.example.json"
    result = api.main(["--catalog", str(seed), "--target-data-dir", str(tmp_path / "operator-data"),
                       "--enable-controlled-runs", "--run-output-dir", str(tmp_path / "not-created")])
    assert result == 0
    assert isinstance(captured["catalog"], ManagedTargetCatalog)
    assert captured["policy"].grants == []
    assert not captured["output_root"].exists()


def test_local_single_user_requires_proxy_credential_and_first_probe_confirmation(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "managed-lab-v1", "credential_aliases": {}, "targets": []})
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data",
        probe_transport=httpx.MockTransport(reply), local_single_user=True)
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True).test_client()
    health = client.get("/api/testing/health", base_url=BASE).json
    assert health["operator_mode"] == "local_single_user"
    headers = {"Origin": BASE, "X-SecAgent-Validation": health["validation_nonce"],
               "X-SecAgent-Operator": SECRET}
    assert post(client, "managed-targets/create", {"profile": profile()},
                {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    assert row["connection_probe"]["status"] == "requires_confirmation"
    selection = {"target_id": row["id"], "profile_revision": row["profile_revision"],
                 "policy_ref": row["policy_ref"]}
    assert post(client, "connection-checks", selection, headers).status_code == 403
    assert post(client, "connection-checks", selection | {"endpoint": "http://127.0.0.1:7000/chat",
        "authorization_confirmed": True}, headers).status_code == 403
    assert post(client, "connection-checks", selection | {"endpoint": row["endpoint"],
        "authorization_confirmed": True}, headers | {"Origin": "http://evil.example"}).status_code == 403
    assert not seen and catalog.public_targets()[0]["authorization_status"] == "review_required"
    result = post(client, "connection-checks", selection | {"endpoint": row["endpoint"],
        "authorization_confirmed": True}, headers)
    assert result.status_code == 200 and result.json["target_request_count"] == len(seen) == 1
    assert catalog.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"
    restarted = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    assert restarted.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"


def test_local_one_click_run_issues_one_use_grant_and_preserves_report(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "SecAgent is a prototype AI agent security testing system."},
            "finish_reason": "stop"}]})
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "managed-lab-v1", "credential_aliases": {}, "targets": []})
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    boundary = tmp_path / "results"
    dispatcher = ControlledDispatcher(catalog, AdmissionPolicy(), boundary / "runs",
        operator_secret=SECRET, transport=httpx.MockTransport(reply), output_boundary=boundary)
    client = create_app(catalog, dispatcher=dispatcher, local_single_user=True).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    row = post(client, "managed-targets/create", {"profile": profile()}, headers).json["profile"]
    draft = {k: row[k] for k in ("profile_revision", "policy_ref", "endpoint", "protocol", "method",
                                  "request_mapping", "response_parser", "credential_alias")}
    draft.update(target_id=row["id"], model=row["default_model"], timeout_seconds=30)
    selection = {"target": draft, "asi_categories": ["ASI01"], "testcase_ids": ["GH-C01"],
                 "target_request_budget": 1, "evaluation_mode": "rule_only"}
    unreviewed = post(client, "readiness/preview", selection, headers).json
    assert "operator_review_required" in unreviewed["blockers"]
    request = selection | {"expected_plan_id": unreviewed["plan_id"],
                           "authorization_confirmed": True, "submission_id": "a" * 32}
    assert post(client, "run-selected", request, headers).status_code == 409
    assert not seen
    review = {"target_id": row["id"], "profile_revision": row["profile_revision"],
        "policy_ref": row["policy_ref"], "endpoint": row["endpoint"],
        "protocol": row["protocol"], "model": row["default_model"],
        "capabilities": ["chat"], "authorization_confirmed": True}
    assert post(client, "managed-targets/review", review, headers).status_code == 200
    preview = post(client, "readiness/preview", selection, headers).json
    request = request | {"expected_plan_id": preview["plan_id"]}
    for altered in (request | {"expected_plan_id": "f" * 64},
                    request | {"testcase_ids": ["GH-001"]},
                    request | {"authorization_confirmed": False}):
        assert post(client, "run-selected", altered, headers).status_code in {400, 409}
    assert post(client, "run-selected", request,
        {k: v for k, v in headers.items() if k != "X-SecAgent-Operator"}).status_code == 403
    assert post(client, "run-selected", request, headers | {"Origin": "http://evil.example"}).status_code == 403
    assert not seen
    completed = post(client, "run-selected", request, headers)
    assert completed.status_code == 200
    result = completed.json
    assert result["execution_status"] == "completed" and result["historical_verdict"] == "PASS"
    assert result["target_request_count"] == len(seen) == 1
    assert result["response_captured"] and result["response_complete"] is True
    assert len(list(dispatcher.output_root.glob("submission-*.json"))) == 1
    assert len(list(dispatcher.output_root.glob("operator-grant-*.json"))) == 1
    assert len(list(dispatcher.output_root.glob("claim-*"))) == 1
    assert post(client, "run-selected", request, headers).status_code == 409
    assert len(seen) == 1
    from reporting.api import create_app as reporting_app
    from reporting.repository import load_dataset
    manifest = tmp_path / "reporting.json"
    manifest.write_text(json.dumps({"dataset_schema_version": "1.0.0",
        "allowed_roots": {"controlled": str(dispatcher.output_root)},
        "controlled_runs_root": "controlled", "reports": [], "verification_jobs": []}), encoding="utf-8")
    detail = reporting_app(load_dataset(manifest)).test_client().get(
        "/api/reports/runs/" + result["run_id"])
    assert detail.status_code == 200
    assert detail.json["execution"]["security"]["verdict"] == "PASS"
    assert detail.json["execution"]["observation"]["response_completeness"]["state"] == "complete"
    active, release = Event(), Event()
    def delayed(target_request):
        seen.append(target_request)
        active.set()
        assert release.wait(5)
        return httpx.Response(200, json={"choices": [{"message": {
            "content": "SecAgent is a prototype AI agent security testing system."},
            "finish_reason": "stop"}]})
    dispatcher.transport = httpx.MockTransport(delayed)
    outcomes = []
    worker = Thread(target=lambda: outcomes.append(post(client.application.test_client(),
        "run-selected", request | {"submission_id": "b" * 32}, headers)))
    worker.start()
    assert active.wait(5)
    concurrent = post(client, "run-selected", request | {"submission_id": "c" * 32}, headers)
    assert concurrent.status_code == 409 and concurrent.json["error"]["code"] == "run_active"
    assert len(seen) == 2
    release.set()
    worker.join(5)
    assert not worker.is_alive() and outcomes[0].status_code == 200
    assert len(list(dispatcher.output_root.glob("submission-*.json"))) == 2
    assert len(list(dispatcher.output_root.glob("claim-*"))) == 2
