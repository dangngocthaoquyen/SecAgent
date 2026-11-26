"""Metadata discovery stays bounded and separate from target review or execution."""
import json
import socket

import httpx
import pytest

from workflow.api import create_app
from workflow.discovery import DiscoveryEngine, DiscoveryRequest, DiscoveryError
from targets.adapters.dvaa_discovery import DvaaEvidenceDiscoveryProvider
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig


BASE = "http://127.0.0.1:8092"
SECRET = "discovery-test-operator-credential-123456"
URL = "http://127.0.0.1:7001/v1/chat/completions"
ITEMS = [{"id": "GH-C01", "asi_category": "ASI01"},
         {"id": "TM-001", "asi_category": "ASI02"}]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden"))


def engine(tmp_path, handler):
    return DiscoveryEngine(tmp_path, transport=httpx.MockTransport(handler))


def discover(service, url=URL, **changes):
    request = DiscoveryRequest(url=url, authorization_confirmed=True, **changes)
    return service.discover(request, allowed_aliases=set(), testcase_items=ITEMS,
                            text_case_ids={"GH-C01"})


def test_openai_metadata_is_advertised_not_runtime_verified(tmp_path):
    seen = []
    def reply(request):
        seen.append((request.method, str(request.url)))
        return (httpx.Response(200, json={"data": [{"id": "securebot"}]})
                if request.url.path == "/v1/models" else httpx.Response(404))
    service = engine(tmp_path, reply)
    result = discover(service)
    assert len(seen) == result["request_count"] == 3
    assert all(method == "GET" for method, _ in seen)
    assert result["proposed_profile"]["model"] == "securebot"
    assert result["canonical_endpoint"] == URL
    assert result["protocol_candidates"][0]["runtime_verified"] is False
    assert result["recommendations"] == [
        {"testcase_id": "GH-C01", "asi_category": "ASI01", "status": "CONDITIONAL",
         "reason": "review_and_runtime_contract_required", "security_verdict": None},
        {"testcase_id": "TM-001", "asi_category": "ASI02", "status": "UNSUPPORTED",
         "reason": "no_reviewed_execution_binding", "security_verdict": None}]
    assert result["security_test_executed"] is False and result["security_verdict"] is None
    assert service.load(result["discovery_id"])["discovery_id"] == result["discovery_id"]
    assert json.loads((tmp_path / "discoveries" / (result["discovery_id"] + ".json")).read_text())["profile_revision"] is None


def test_openapi_and_a2a_metadata_only_suggest_a_chat_contract(tmp_path):
    def reply(request):
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/v1/chat/completions": {"post": {}}}})
        if request.url.path == "/.well-known/agent.json":
            return httpx.Response(200, json={"name": "Example Agent", "skills": [{"name": "summarize"}]})
        return httpx.Response(404)
    row = discover(engine(tmp_path, reply), "http://127.0.0.1:7001/")
    assert row["canonical_endpoint"] == URL
    assert {p["id"] for p in row["protocol_candidates"]} == {"openai-chat", "openapi-http", "a2a"}
    assert row["advertised_skills"][0]["name"] == "summarize"
    assert row["advertised_tools"] == []
    assert all(p["runtime_verified"] is False for p in row["protocol_candidates"])


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "http://example.com:7001/v1/chat/completions",
    "http://localhost:7001/v1/chat/completions", "http://169.254.169.254:80/",
    "http://10.0.0.1:7001/", "http://user:secret@127.0.0.1:7001/",
    "http://127.0.0.1:7001/?token=secret", "http://127.0.0.1:7001/api/../other",
    "http://127.0.0.1:7001//other",
    "http://127.0.0.1:7001/%2e%2e/", "http://127.0.0.1:7001\\@evil.example/",
    "http://127.0.0.1:7001/\n", "http://127.0.0.1:7001/#fragment",
])
def test_unsafe_urls_never_reach_transport(tmp_path, url):
    service = engine(tmp_path, lambda _: pytest.fail("Unexpected discovery request"))
    with pytest.raises(DiscoveryError):
        discover(service, url)


def test_missing_malformed_timeout_and_connection_failure_remain_unknown(tmp_path):
    def reply(request):
        if request.url.path == "/v1/models":
            return httpx.Response(200, content=b"not-json")
        if request.url.path == "/openapi.json":
            raise httpx.ReadTimeout("offline timeout")
        raise httpx.ConnectError("offline failure")
    row = discover(engine(tmp_path, reply), "http://127.0.0.1:7001/")
    assert row["status"] == "manual_configuration_required"
    assert row["proposed_profile"] is None
    assert [p["status"] for p in row["metadata_sources"]] == [
        "malformed", "timeout", "connection_failure"]
    assert row["recommendations"][0]["status"] == "UNKNOWN"


def test_redirect_and_oversize_fail_closed(tmp_path):
    for response, code in [(httpx.Response(302, headers={"Location": "http://evil.example/"}),
                            "discovery_redirect_rejected"),
                           (httpx.Response(200, content=b"x" * 16385),
                            "discovery_response_too_large")]:
        seen = []
        def reply(request):
            seen.append(str(request.url))
            return response
        with pytest.raises(DiscoveryError) as failure:
            discover(engine(tmp_path, reply))
        assert failure.value.code == code
        assert len(seen) == 1


def test_real_api_auth_revision_association_and_no_execution(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        return (httpx.Response(200, json={"data": [{"id": "advertised-model"}]})
                if request.url.path == "/v1/models" else httpx.Response(404))
    seed = CatalogConfig(catalog_schema_version="1.0.0", policy_ref="discovery-test-v1",
                         credential_aliases={}, targets=[])
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True,
                        discovery_transport=httpx.MockTransport(reply)).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": SECRET}
    route = "/api/testing/discoveries"
    body = {"url": URL, "authorization_confirmed": True}
    assert client.post(route, base_url=BASE, json=body, headers={"Origin": BASE,
        "X-SecAgent-Validation": nonce}).status_code == 403
    assert client.post(route, base_url=BASE, json=body, headers=headers |
        {"Origin": "http://evil.example"}).status_code == 403
    assert client.post(route, base_url=BASE, json=body, headers={k:v for k,v in headers.items()
        if k != "X-SecAgent-Validation"}).status_code == 403
    assert len(seen) == 0
    result = client.post(route, base_url=BASE, json=body, headers=headers)
    assert result.status_code == 200
    row = result.json
    assert row["request_count"] == 3
    assert len(row["recommendations"]) == len(client.get(
        "/api/testing/testcases", base_url=BASE).json["items"])
    assert all(item["status"] != "SUPPORTED" for item in row["recommendations"])
    assert client.get(route + "/" + row["discovery_id"], base_url=BASE).status_code == 403
    assert client.get(route + "/" + row["discovery_id"], base_url=BASE,
                      headers={"X-SecAgent-Operator": SECRET}).status_code == 200
    profile = row["proposed_profile"] | {"id": "discovered-agent", "name": "Reviewed Candidate",
                                          "model": "operator-corrected"}
    saved = client.post("/api/testing/managed-targets/create", base_url=BASE,
                        json={"profile": profile, "discovery_id": row["discovery_id"]},
                        headers=headers)
    assert saved.status_code == 200
    target = saved.json["profile"]
    assert target["authorization_status"] == "review_required"
    stored = DiscoveryEngine(tmp_path / "operator-data").load(row["discovery_id"])
    assert stored["saved_target_id"] == target["id"]
    assert stored["profile_revision"] == target["profile_revision"]
    assert client.post("/api/testing/managed-targets/create", base_url=BASE,
                       json={"profile": profile | {"id": "other"},
                             "discovery_id": row["discovery_id"]}, headers=headers).status_code == 409
    assert client.post("/api/testing/managed-targets/create", base_url=BASE,
                       json={"profile": profile | {"id": "bad", "endpoint":
                             "http://127.0.0.1:7002/v1/chat/completions"},
                             "discovery_id": row["discovery_id"]}, headers=headers).status_code == 409
    assert client.post("/api/testing/managed-targets/create", base_url=BASE,
                       json={"profile": profile | {"id": "wrong-protocol", "protocol": "mcp-jsonrpc"},
                             "discovery_id": row["discovery_id"]}, headers=headers).status_code == 409
    assert catalog.public_targets()[0]["authorization_status"] == "review_required"
    assert len(seen) == 3
    restarted = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True)
    assert restarted.public_targets()[0]["id"] == target["id"]


def test_mcp_discovery_uses_only_tools_list_and_proposes_unreviewed_profile(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        payload = json.loads(request.content)
        assert payload["method"] == "tools/list" and payload["params"] == {}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"],
            "result": {"tools": [{"name": "read_file", "description": "untrusted"}]}})
    service = DiscoveryEngine(tmp_path, transport=httpx.MockTransport(reply),
        evidence_providers=(DvaaEvidenceDiscoveryProvider(),))
    row = discover(service, "http://127.0.0.1:7010/", protocol_hint="mcp-jsonrpc")
    assert len(seen) == row["request_count"] == 1
    assert seen[0].method == "POST" and seen[0].url.path == "/"
    assert row["proposed_profile"]["protocol"] == "mcp-jsonrpc"
    assert row["proposed_profile"]["endpoint"] == "http://127.0.0.1:7010/"
    assert row["advertised_tools"][0]["name"] == "read_file"
    assert "untrusted" not in json.dumps(row)
    assert row["connection_status"] == "reachable"
    assert row["protocol_candidates"][0]["runtime_verified"] is False
    assert len(row["evidence_candidates"]) == 3
    assert all(item["availability"] == "candidate_needs_review" and
               item["verification_status"] == "not_verified" for item in row["evidence_candidates"])
    assert row["security_test_executed"] is False


def test_mcp_malformed_or_wrong_identity_never_proposes_profile(tmp_path):
    for body in ({"jsonrpc": "2.0", "id": "wrong", "result": {"tools": []}},
                 {"jsonrpc": "2.0", "id": "secagent-discovery", "result": {"tools": "bad"}}):
        row = discover(engine(tmp_path, lambda _: httpx.Response(200, json=body)),
            "http://127.0.0.1:7010/mcp", protocol_hint="mcp-jsonrpc")
        assert row["proposed_profile"] is None
        assert row["evidence_candidates"] == []


def test_unknown_mcp_adapter_has_no_dvaa_evidence_suggestions(tmp_path):
    def reply(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "secagent-discovery",
            "result": {"tools": [{"name": "read_file"}]}})
    service = DiscoveryEngine(tmp_path, transport=httpx.MockTransport(reply),
        evidence_providers=(DvaaEvidenceDiscoveryProvider(),))
    for port in (7450, 7110):
        row = discover(service, f"http://127.0.0.1:{port}/", protocol_hint="mcp-jsonrpc")
        assert row["proposed_profile"]["protocol"] == "mcp-jsonrpc"
        assert row["evidence_candidates"] == []


def test_dashboard_without_manifest_does_not_imply_agent_endpoints(tmp_path):
    row = discover(engine(tmp_path, lambda _: httpx.Response(404)),
        "http://127.0.0.1:9000/")
    assert row["proposed_profile"] is None
    assert row["protocol_candidates"] == []


def test_mcp_redirect_and_large_response_fail_closed_after_one_request(tmp_path):
    for response, code in ((httpx.Response(302, headers={"Location": "http://127.0.0.1:9000/"}),
                            "discovery_redirect_rejected"),
                           (httpx.Response(200, content=b"x" * 16385),
                            "discovery_response_too_large")):
        seen = []
        service = engine(tmp_path, lambda request: (seen.append(request), response)[1])
        with pytest.raises(DiscoveryError) as failure:
            discover(service, "http://127.0.0.1:7010/", protocol_hint="mcp-jsonrpc")
        assert failure.value.code == code and len(seen) == 1


def test_quick_connect_mcp_probe_is_bound_to_discovery_and_does_not_save(tmp_path):
    seen = []
    def reply(request):
        seen.append(request)
        payload = json.loads(request.content)
        assert payload["method"] == "tools/list"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"],
            "result": {"tools": [{"name": "read_file"}]}})
    seed = CatalogConfig(catalog_schema_version="1.0.0", policy_ref="quick-connect-test-v1",
                         credential_aliases={}, targets=[])
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True,
                                   probe_transport=httpx.MockTransport(reply))
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True,
                        discovery_transport=httpx.MockTransport(reply)).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    discovered = client.post("/api/testing/discoveries", base_url=BASE, headers=headers,
        json={"url": "http://127.0.0.1:7010/", "authorization_confirmed": True}).json
    assert discovered["proposed_profile"]["protocol"] == "mcp-jsonrpc"
    assert discovered["adapter_protocol_hint"] == "mcp-jsonrpc"
    assert len(seen) == 1
    request = {"profile": discovered["proposed_profile"],
               "discovery_id": discovered["discovery_id"], "authorization_confirmed": True}
    route = "/api/testing/discovery-probes"
    assert client.post(route, base_url=BASE, headers=headers,
                       json=request | {"authorization_confirmed": False}).status_code == 400
    assert client.post(route, base_url=BASE, headers=headers,
                       json=request | {"profile": request["profile"] | {"endpoint": "http://127.0.0.1:7011/"}}).status_code == 409
    assert len(seen) == 1
    probed = client.post(route, base_url=BASE, headers=headers, json=request)
    assert probed.status_code == 200
    assert probed.json["connection_status"] == "succeeded"
    assert probed.json["target_request_count"] == 1
    assert len(seen) == 2
    assert all(json.loads(row.content)["method"] == "tools/list" for row in seen)
    assert catalog.public_targets() == []


def test_provisional_mcp_probe_accepts_an_already_saved_identifier_without_mutation(tmp_path):
    seen = []
    def mcp(request):
        payload = json.loads(request.content)
        seen.append((str(request.url), request.method, request.headers.get("content-type"), payload))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": payload["id"],
            "result": {"tools": [{"name": "read_file"}]}})
    seed = CatalogConfig.model_validate({"catalog_schema_version": "1.0.0",
        "policy_ref": "quick-connect-test-v1", "credential_aliases": {}, "targets": [{
            "id": "local-agent-7010", "name": "Previously saved ToolBot",
            "platform_id": "local-agent", "platform_name": "Local Agent",
            "protocol": "mcp-jsonrpc", "endpoint": "http://127.0.0.1:7010/",
            "models": ["mcp-service"], "default_model": "mcp-service"}]})
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True,
                                   probe_transport=httpx.MockTransport(mcp))
    before = catalog.public_targets()
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True,
                        discovery_transport=httpx.MockTransport(mcp)).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": SECRET}
    discovered = client.post("/api/testing/discoveries", base_url=BASE, headers=headers,
        json={"url": "http://127.0.0.1:7010/", "authorization_confirmed": True}).json
    assert discovered["proposed_profile"]["id"] == "local-agent-7010"
    request = {"profile": discovered["proposed_profile"],
               "discovery_id": discovered["discovery_id"], "authorization_confirmed": True}
    assert client.post("/api/testing/discovery-probes", base_url=BASE,
                       headers={"Origin": BASE, "X-SecAgent-Validation": nonce}, json=request).status_code == 403
    assert len(seen) == 1
    probed = client.post("/api/testing/discovery-probes", base_url=BASE,
                         headers=headers, json=request)
    assert probed.status_code == 200
    assert probed.json["connection_status"] == "succeeded"
    assert probed.json["reason"] == "mcp_tools_list_response"
    assert probed.json["target_request_count"] == 1
    assert len(seen) == 2 and catalog.public_targets() == before
    assert all(url == "http://127.0.0.1:7010/" and method == "POST"
               and content_type == "application/json" and body["method"] == "tools/list"
               and body["jsonrpc"] == "2.0" for url, method, content_type, body in seen)
    assert seen[1][3]["id"] == "secagent-connection-check"


@pytest.mark.parametrize("invalid", ["malformed", "wrong_id"])
def test_provisional_mcp_probe_rejects_invalid_response_contract(tmp_path, invalid):
    def metadata(request):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "secagent-discovery",
            "result": {"tools": [{"name": "read_file"}]}})
    def probe(request):
        if invalid == "malformed":
            return httpx.Response(200, content=b"not-json")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "different-id",
            "result": {"tools": [{"name": "read_file"}]}})
    seed = CatalogConfig(catalog_schema_version="1.0.0", policy_ref="quick-connect-test-v1",
                         credential_aliases={}, targets=[])
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True,
                                   probe_transport=httpx.MockTransport(probe))
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True,
                        discovery_transport=httpx.MockTransport(metadata)).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce,
               "X-SecAgent-Operator": SECRET}
    discovered = client.post("/api/testing/discoveries", base_url=BASE, headers=headers,
        json={"url": "http://127.0.0.1:7010/", "authorization_confirmed": True}).json
    result = client.post("/api/testing/discovery-probes", base_url=BASE, headers=headers,
        json={"profile": discovered["proposed_profile"],
              "discovery_id": discovered["discovery_id"], "authorization_confirmed": True})
    assert result.status_code == 200
    assert result.json["connection_status"] == "incompatible"
    assert result.json["reason"] == "response_contract_unverified"
    assert catalog.public_targets() == []


def test_quick_connect_http_requires_operator_model_and_keeps_profile_unsaved(tmp_path):
    seen = []
    def metadata(request):
        return httpx.Response(404)
    def chat(request):
        seen.append(request)
        assert json.loads(request.content)["model"] == "default"
        return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}}]})
    seed = CatalogConfig(catalog_schema_version="1.0.0", policy_ref="quick-connect-test-v1",
                         credential_aliases={}, targets=[])
    catalog = ManagedTargetCatalog(seed, tmp_path / "operator-data", local_single_user=True,
                                   probe_transport=httpx.MockTransport(chat))
    client = create_app(catalog, operator_secret=SECRET, local_single_user=True,
                        discovery_transport=httpx.MockTransport(metadata)).test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    row = client.post("/api/testing/discoveries", base_url=BASE, headers=headers,
        json={"url": "http://127.0.0.1:7004/v1/chat/completions",
              "authorization_confirmed": True}).json
    assert row["proposed_profile"]["model"] == ""
    probe = {"discovery_id": row["discovery_id"], "authorization_confirmed": True,
             "profile": row["proposed_profile"]}
    assert client.post("/api/testing/discovery-probes", base_url=BASE, headers=headers,
                       json=probe).status_code == 400
    assert seen == []
    result = client.post("/api/testing/discovery-probes", base_url=BASE, headers=headers,
                         json=probe | {"profile": probe["profile"] | {"model": "default"}})
    assert result.status_code == 200
    assert result.json["connection_status"] == "succeeded"
    assert len(seen) == 1 and catalog.public_targets() == []
