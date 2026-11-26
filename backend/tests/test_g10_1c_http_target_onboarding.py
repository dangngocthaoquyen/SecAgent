"""G10.1C regression & acceptance tests: Universal HTTP Target Onboarding Upgrade.

Strictly offline: real sockets are blocked; all HTTP/MCP interactions use controlled
synthetic local MockTransport fixtures. No live DVAA or AIGoat requests are made.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
from typing import Any

import httpx
import pytest

from core.models import TestInput
from targets.adapters.http_adapter import HttpTargetAdapter, format_bearer_header_value
from workflow.api import create_app
from workflow.catalog import make_profile
from workflow.dataset_repository import DatasetRepository
from workflow.discovery import DiscoveryEngine, DiscoveryError, DiscoveryRequest
from workflow.dispatch import ControlledDispatcher
from workflow.admission import AdmissionPolicy
from workflow.generic_imported_batch import GenericImportedBatchWorkflow
from workflow.management import ManagedTargetCatalog
from workflow.models import CatalogConfig
from workflow.response_inspector import inspect_http_response_shape
from workflow.response_policies import ResponsePolicyStore
from workflow.routes_generic_runner import GenericRunService


BASE = "http://127.0.0.1:8092"
SECRET = "g10-1c-operator-secret-token-" + "x" * 32


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    monkeypatch.setattr(
        socket.socket, "connect", lambda *_: pytest.fail("Real network forbidden in G10.1C offline tests")
    )


def _agent_runs_openapi_doc() -> dict[str, Any]:
    """Synthetic OpenAPI fixture modeling an authenticated REST agent run API with untyped steps."""
    return {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
            },
            "schemas": {
                "AgentRunIn": {
                    "type": "object",
                    "required": ["lab_id", "goal"],
                    "properties": {
                        "lab_id": {"type": "string"},
                        "goal": {"type": "string"},
                        "session_token": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
                        "defense_level": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
                    },
                },
                "AgentRunOut": {
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "status": {"type": "string"},
                        "answer": {"type": "string"},
                        "steps": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
        "paths": {
            "/api/agent/runs": {
                "post": {
                    "operationId": "create_run",
                    "summary": "Create Agent Run",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AgentRunIn"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/AgentRunOut"}
                                }
                            }
                        }
                    },
                }
            },
            "/api/secondary/ping": {
                "post": {
                    "operationId": "secondary_ping",
                    "summary": "Secondary Operation",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["message"],
                                    "properties": {"message": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"reply": {"type": "string"}},
                                    }
                                }
                            }
                        }
                    },
                }
            },
        },
    }


def _nested_execute_openapi_doc() -> dict[str, Any]:
    """Scenario C: Unrelated synthetic HTTP Agent with nested request & nested response."""
    return {
        "openapi": "3.1.0",
        "paths": {
            "/v2/execute": {
                "post": {
                    "operationId": "execute_task",
                    "summary": "Execute Nested Task",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["workspace", "task"],
                                    "properties": {
                                        "workspace": {"type": "string"},
                                        "task": {
                                            "type": "object",
                                            "required": ["query"],
                                            "properties": {
                                                "query": {"type": "string"},
                                            },
                                        },
                                    },
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "result": {
                                                        "type": "object",
                                                        "properties": {
                                                            "text": {"type": "string"},
                                                        },
                                                    }
                                                },
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    }


def _setup_api(
    tmp_path: Path,
    *,
    credential_aliases: dict[str, str] | None = None,
    discovery_transport: httpx.BaseTransport | None = None,
    probe_transport: httpx.BaseTransport | None = None,
    local_single_user: bool = True,
    seed_targets: list[dict[str, Any]] | None = None,
):
    seed = {
        "catalog_schema_version": "1.0.0",
        "policy_ref": "g10-1c-policy-v1",
        "credential_aliases": credential_aliases or {},
        "targets": seed_targets or [],
    }
    data_dir = tmp_path / "operator-data"
    catalog = ManagedTargetCatalog(
        CatalogConfig.model_validate(seed),
        data_dir,
        probe_transport=probe_transport,
        local_single_user=local_single_user,
    )
    results_boundary = tmp_path / "results"
    dispatcher = ControlledDispatcher(
        catalog,
        AdmissionPolicy(),
        results_boundary / "controlled-runs",
        operator_secret=SECRET,
        transport=None,
        output_boundary=results_boundary,
    )
    dataset_repo = DatasetRepository(data_dir)
    imported_service = GenericImportedBatchWorkflow(
        dispatcher,
        dataset_repo,
        execution_mode="both",
        mock_live_transport=probe_transport,
    )
    policy_store = ResponsePolicyStore(data_dir / "response_policies")
    gen_service = GenericRunService(
        catalog=catalog,
        dataset_repo=dataset_repo,
        inventory=None,
        policy_store=policy_store,
        runs_root=tmp_path / "generic-runs",
    )
    app = create_app(
        catalog,
        dispatcher=dispatcher,
        operator_secret=SECRET,
        local_single_user=local_single_user,
        batch_services={"imported": imported_service},
        discovery_transport=discovery_transport,
        generic_run_service=gen_service,
    )
    # Override imported_service transport overwrite on discovery/probe when explicitly injected.
    if discovery_transport is not None:
        app.config["TESTING"] = True
    client = app.test_client()
    nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
    headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}
    return catalog, gen_service, client, headers


# ---------------------------------------------------------------------------
# A. Discovery Regression (F-01, F-05, F-08, F-12, Clarification #3 & #5)
# ---------------------------------------------------------------------------


def test_f01_f08_f12_automatic_rest_discovery_selects_exact_operation_and_preserves_unresolved_fields(tmp_path):
    """Automatic discovery accepts custom REST path, sends GET metadata only, selects exact operation, emits http-json metadata."""
    seen: list[tuple[str, str]] = []
    doc = _agent_runs_openapi_doc()

    def handler(req: httpx.Request):
        seen.append((req.method, str(req.url)))
        if req.url.path == "/openapi.json":
            return httpx.Response(200, json=doc)
        return httpx.Response(404)

    eng = DiscoveryEngine(tmp_path, transport=httpx.MockTransport(handler))
    res = eng.discover(
        DiscoveryRequest(url="http://127.0.0.1:8000/api/agent/runs", authorization_confirmed=True),
        allowed_aliases={"agent_token"},
        testcase_items=[{"id": "GH-C01", "asi_category": "ASI01"}],
        text_case_ids={"GH-C01"},
    )

    # Bounded same-origin GET metadata requests only; ZERO POST requests!
    assert len(seen) == res["request_count"] == 3
    assert all(method == "GET" for method, _ in seen)
    assert all(url.startswith("http://127.0.0.1:8000/") for _, url in seen)

    # Exact operation auto-selected as unconfirmed review draft with model=None and unresolved lab_id!
    assert res["exact_match_path"] == "/api/agent/runs"
    assert res["configuration_readiness"] == "incomplete_configuration"
    proposed = res["proposed_profile"]
    assert proposed is not None
    assert proposed["protocol"] == "http-json"
    assert proposed["endpoint"] == "http://127.0.0.1:8000/api/agent/runs"
    assert proposed["model"] is None
    # Optional defense_level with null default MUST be omitted (Clarification #3)!
    assert proposed["http_config"]["body_template"] == {"lab_id": "<REQUIRED:lab_id>", "goal": "{{input}}"}
    assert "defense_level" not in proposed["http_config"]["body_template"]
    assert proposed["http_config"]["response"]["text_path"] == "answer"
    assert proposed["http_config"]["response"]["correlation_id_path"] == "run_id"
    assert proposed["http_config"]["response"]["status_path"] == "status"

    # F-12: Correct protocol & contract metadata (NEVER mislabeled as OpenAI-compatible!)
    assert any(p["id"] == "http-json" for p in res["protocol_candidates"])
    assert not any(p["id"] == "openai-chat" for p in res["protocol_candidates"])
    assert res["possible_contracts"] == [
        {
            "request": "http-json-template-v1",
            "response": "answer",
            "classification": "advertised_metadata_unverified",
        }
    ]
    assert "runtime_chat_contract" not in res["unknown_fields"]
    assert "runtime_http_contract" in res["unknown_fields"]
    assert "unresolved_required_request_parameters" in res["unknown_fields"]
    assert "authentication_credential_alias" in res["unknown_fields"]
    assert "response_completion_semantics" in res["unknown_fields"]
    assert "ambiguous_openapi_operation_selection" not in res["unknown_fields"]

    # Security integrity: auto-selected proposed_profile MUST NOT bypass auth checks in validate_association!
    with pytest.raises(DiscoveryError, match="discovery_authentication_required"):
        eng.validate_association(res["discovery_id"], "http://127.0.0.1:8000/api/agent/runs", "http-json")
    eng.validate_association(
        res["discovery_id"],
        "http://127.0.0.1:8000/api/agent/runs",
        "http-json",
        credential_alias="agent_token",
    )


def test_clarification5_exact_missing_endpoint_never_silently_substitutes_other_operation(tmp_path):
    """When operator supplies a specific REST path absent from OpenAPI, do NOT silently substitute another op or chat path."""
    doc = {
        "openapi": "3.1.0",
        "paths": {
            "/v1/chat/completions": {"post": {}},
            "/api/other/run": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["prompt"],
                                    "properties": {"prompt": {"type": "string"}},
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"answer": {"type": "string"}},
                                    }
                                }
                            }
                        }
                    },
                }
            },
        },
    }
    eng = DiscoveryEngine(
        tmp_path,
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=doc) if req.url.path == "/openapi.json" else httpx.Response(404)
        ),
    )
    res = eng.discover(
        DiscoveryRequest(url="http://127.0.0.1:8000/api/nonexistent/agent", authorization_confirmed=True),
        allowed_aliases=set(),
        testcase_items=[],
        text_case_ids=set(),
    )
    assert res["proposed_profile"] is None
    assert res["canonical_endpoint"] is None
    assert res["exact_match_path"] is None
    assert res["configuration_readiness"] == "selection_required"
    assert any("was not found" in w for w in res["warnings"])


def test_f05_auth_discovery_distinguishes_required_may_be_required_not_declared_and_unsupported(tmp_path):
    doc = {
        "openapi": "3.1.0",
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
                "BasicAuth": {"type": "http", "scheme": "basic"},
            }
        },
        "paths": {
            "/api/req-bearer": {
                "post": {
                    "security": [{"BearerAuth": []}],
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"answer": {"type": "string"}}}}}}},
                }
            },
            "/api/opt-header": {
                "post": {
                    "security": [],
                    "parameters": [{"name": "Authorization", "in": "header", "required": False}],
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"answer": {"type": "string"}}}}}}},
                }
            },
            "/api/middleware-hint": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"answer": {"type": "string"}}}}}}},
                }
            },
            "/api/explicit-open": {
                "post": {
                    "security": [],
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"answer": {"type": "string"}}}}}}},
                }
            },
            "/api/unsupported-basic": {
                "post": {
                    "security": [{"BasicAuth": []}],
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"prompt": {"type": "string"}}}}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object", "properties": {"answer": {"type": "string"}}}}}}},
                }
            },
        },
    }
    eng = DiscoveryEngine(
        tmp_path,
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=doc) if req.url.path == "/openapi.json" else httpx.Response(404)
        ),
    )
    res = eng.discover(
        DiscoveryRequest(url="http://127.0.0.1:8000/", authorization_confirmed=True),
        allowed_aliases=set(),
        testcase_items=[],
        text_case_ids=set(),
    )
    by_path = {c["path"]: c for c in res["openapi_candidates"]}
    assert by_path["/api/req-bearer"]["auth_status"] == "required"
    assert by_path["/api/req-bearer"]["requires_auth"] is True

    assert by_path["/api/opt-header"]["auth_status"] == "may_be_required"
    assert by_path["/api/opt-header"]["requires_auth"] is False
    assert "optional_header:authorization" in by_path["/api/opt-header"]["auth_hints"]

    assert by_path["/api/middleware-hint"]["auth_status"] == "may_be_required"
    assert by_path["/api/middleware-hint"]["requires_auth"] is False
    assert "security_schemes_declared_in_spec" in by_path["/api/middleware-hint"]["auth_hints"]

    assert by_path["/api/explicit-open"]["auth_status"] == "not_declared"
    assert by_path["/api/explicit-open"]["requires_auth"] is False
    assert any("does not verify anonymous access" in lim for lim in by_path["/api/explicit-open"]["limitations"])

    assert by_path["/api/unsupported-basic"]["auth_status"] == "unsupported"
    assert by_path["/api/unsupported-basic"]["requires_auth"] is True
    assert by_path["/api/unsupported-basic"]["auth_scheme_supported"] is False


# ---------------------------------------------------------------------------
# B & C. Shared HTTP Connection Test, Auth Parity, Redaction & Timeout (F-02, F-03, F-07)
# ---------------------------------------------------------------------------


def test_f07_bearer_formatting_parity_between_probe_and_real_http_execution(tmp_path, monkeypatch):
    """Both raw tokens and pre-prefixed 'Bearer ...' tokens produce exact single 'Bearer <tok>' in probe AND adapter execution."""
    for env_val in ("SYNTH_TOKEN_ABC123", "Bearer SYNTH_TOKEN_ABC123", "  bearer   SYNTH_TOKEN_ABC123 "):
        monkeypatch.setenv("G10_PARITY_TOKEN", env_val)
        assert format_bearer_header_value(env_val) == "Bearer SYNTH_TOKEN_ABC123"

        captured_probe: list[dict[str, Any]] = []

        def probe_handler(req: httpx.Request):
            captured_probe.append({
                "method": req.method,
                "url": str(req.url),
                "auth": req.headers.get("authorization"),
                "body": json.loads(req.content),
            })
            return httpx.Response(200, json={"answer": "Parity ok", "status": "completed"})

        seed = CatalogConfig.model_validate({
            "catalog_schema_version": "1.0.0",
            "policy_ref": "parity-v1",
            "credential_aliases": {"parity_alias": "G10_PARITY_TOKEN"},
            "targets": [],
        })
        catalog = ManagedTargetCatalog(seed, tmp_path / f"data-{abs(hash(env_val))}", probe_transport=httpx.MockTransport(probe_handler))
        from workflow.management import ManagedProfile
        mp = ManagedProfile.model_validate({
            "id": "parity-http",
            "name": "Parity HTTP",
            "platform_id": "lab",
            "platform_name": "Lab",
            "endpoint": "http://127.0.0.1:8000/api/agent/runs",
            "protocol": "http-json",
            "model": None,
            "timeout_seconds": 300,
            "credential_alias": "parity_alias",
            "http_config": {
                "method": "POST",
                "body_template": {"lab_id": "lab-1", "goal": "{{input}}"},
                "headers": {"X-Lab": "parity"},
                "response": {"text_path": "answer", "status_path": "status", "complete_status_values": ["completed"]},
            },
        })
        result, status = catalog.probe_candidate(mp, sample_input="hello parity")
        assert status == 200
        assert result.connection_status == "succeeded"
        assert result.target_request_count == 1
        assert len(captured_probe) == 1
        assert captured_probe[0]["auth"] == "Bearer SYNTH_TOKEN_ABC123"

        # Compare with normal HttpTargetAdapter.prepare_request on the same Preset!
        preset = catalog._preset(mp)
        target_profile = make_profile(preset, preset.default_model, preset.timeout_default, "G10_PARITY_TOKEN")
        method, url, headers, body, _timeout = HttpTargetAdapter.prepare_request(
            target_profile, TestInput(id="t1", prompt="hello parity")
        )
        assert method == captured_probe[0]["method"]
        assert url == captured_probe[0]["url"]
        assert headers["Authorization"] == captured_probe[0]["auth"] == "Bearer SYNTH_TOKEN_ABC123"
        assert body == captured_probe[0]["body"] == {"lab_id": "lab-1", "goal": "hello parity"}

        # Redaction check: secret must NEVER appear in probe diagnostics!
        dumped = json.dumps(result.model_dump())
        assert "SYNTH_TOKEN_ABC123" not in dumped


def test_f03_http_json_probe_diagnostics_statuses_sample_probe_timeout_and_redaction(tmp_path, monkeypatch):
    """Test 401, 403, 422, 200-invalid-mapping, 200-sample-probe-without-text-path, timeout (up to 600s), connect error, missing creds."""
    monkeypatch.setenv("G10_DIAG_TOKEN", "SUPER_SECRET_DIAG_TOKEN_999")
    scenario_response: dict[str, Any] = {"mode": "200_ok"}
    request_counter = {"count": 0}

    def handler(req: httpx.Request):
        request_counter["count"] += 1
        mode = scenario_response["mode"]
        if mode == "401":
            return httpx.Response(401, json={"detail": "Not authenticated"})
        if mode == "403":
            return httpx.Response(403, json={"detail": "Insufficient role"})
        if mode == "422":
            return httpx.Response(422, json={"detail": [{"loc": ["body", "lab_id"], "msg": "field required"}]})
        if mode == "timeout":
            raise httpx.ReadTimeout("slow agent timed out")
        if mode == "connect_error":
            raise httpx.ConnectError("connection refused")
        if mode == "non_json":
            return httpx.Response(200, text="<html>not json</html>")
        if mode == "200_nested_with_secret_echo":
            return httpx.Response(
                200,
                json={
                    "run_id": "run-555",
                    "status": "completed",
                    "data": {"result": {"text": "Answer echoing SUPER_SECRET_DIAG_TOKEN_999 safely"}},
                    "steps": [
                        {
                            "seq": 1,
                            "action": "search_docs",
                            "action_input": {"q": "policy"},
                            "decision": "allow",
                            "observation": "found",
                        }
                    ],
                },
            )
        return httpx.Response(200, json={"answer": "OK", "status": "completed"})

    seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "diag-v1",
        "credential_aliases": {"diag_alias": "G10_DIAG_TOKEN", "missing_alias": "G10_UNSET_TOKEN"},
        "targets": [],
    })
    catalog = ManagedTargetCatalog(seed, tmp_path / "data", probe_transport=httpx.MockTransport(handler))
    from workflow.management import ManagedProfile

    def _mp(text_path: str = "answer", alias: str | None = "diag_alias", timeout: int = 360) -> ManagedProfile:
        return ManagedProfile.model_validate({
            "id": "diag-http",
            "name": "Diag HTTP",
            "platform_id": "lab",
            "platform_name": "Lab",
            "endpoint": "http://127.0.0.1:8000/api/agent/runs",
            "protocol": "http-json",
            "model": None,
            "timeout_seconds": timeout,
            "credential_alias": alias,
            "http_config": {
                "method": "POST",
                "body_template": {"lab_id": "lab-1", "goal": "{{input}}"},
                "headers": {},
                "response": {"text_path": text_path, "status_path": "status"},
            },
        })

    # 1. Missing credentials -> 0 requests!
    res_miss, _ = catalog.probe_candidate(_mp(alias="missing_alias"))
    assert res_miss.connection_status == "unavailable"
    assert res_miss.reason == "credential_unavailable"
    assert res_miss.diagnostic_category == "missing_credentials"
    assert res_miss.target_request_count == 0
    assert request_counter["count"] == 0

    # 2. HTTP 401 -> authentication guidance
    scenario_response["mode"] = "401"
    res_401, _ = catalog.probe_candidate(_mp())
    assert res_401.http_status == 401
    assert res_401.diagnostic_category == "http_authentication_failure"
    assert res_401.verification_state == "authentication_failed"
    assert "401" in (res_401.guidance or "")
    assert res_401.target_request_count == 1

    # 3. HTTP 403 -> permission guidance
    scenario_response["mode"] = "403"
    res_403, _ = catalog.probe_candidate(_mp())
    assert res_403.http_status == 403
    assert res_403.diagnostic_category == "http_permission_failure"
    assert res_403.verification_state == "permission_denied"
    assert "403" in (res_403.guidance or "")

    # 4. HTTP 422 -> request/schema validation guidance
    scenario_response["mode"] = "422"
    res_422, _ = catalog.probe_candidate(_mp())
    assert res_422.http_status == 422
    assert res_422.diagnostic_category == "http_request_validation_failure"
    assert res_422.runtime_protocol_compatible is False
    assert "422" in (res_422.guidance or "")

    # 5. Timeout (360s configured, no retry, warns remote agent may still run)
    before_timeout = request_counter["count"]
    scenario_response["mode"] = "timeout"
    res_to, _ = catalog.probe_candidate(_mp(timeout=360))
    assert res_to.reason == "connection_timeout"
    assert res_to.diagnostic_category == "timeout"
    assert res_to.target_request_count == 1
    assert request_counter["count"] == before_timeout + 1  # Strictly 1 request, zero retry!
    assert "does not imply that the remote Agent stopped executing" in (res_to.guidance or "")

    # 6. Connection failure
    scenario_response["mode"] = "connect_error"
    res_conn, _ = catalog.probe_candidate(_mp())
    assert res_conn.reason == "connection_refused_or_unreachable"
    assert res_conn.diagnostic_category == "network_connection_failure"

    # 7. HTTP 200 non-JSON
    scenario_response["mode"] = "non_json"
    res_nj, _ = catalog.probe_candidate(_mp())
    assert res_nj.connection_status == "incompatible"
    assert res_nj.diagnostic_category == "invalid_response_format"
    assert res_nj.runtime_protocol_compatible is False

    # 8. Clarification #2: Sample probe with EMPTY text_path avoids deadlock,
    #    does NOT mark verified, returns suggestions & redacted response_sample!
    scenario_response["mode"] = "200_nested_with_secret_echo"
    res_sample, _ = catalog.probe_candidate(_mp(text_path=""))
    assert res_sample.http_status == 200
    assert res_sample.connection_status == "incompatible"
    assert res_sample.connection_reachable is True
    assert res_sample.runtime_protocol_compatible is False
    assert res_sample.verification_state == "response_mapping_unresolved"
    assert res_sample.security_test_executed is False
    assert res_sample.security_verdict is None
    assert res_sample.response_sample is not None
    # Secret must be redacted EVERYWHERE!
    assert "SUPER_SECRET_DIAG_TOKEN_999" not in json.dumps(res_sample.model_dump())
    # Nested path suggestion discovered!
    sugg = res_sample.mapping_diagnostics["suggestions"]
    assert sugg["text_path_candidates"][0]["path"] == "data.result.text"
    assert sugg["correlation_id_candidates"][0]["path"] == "run_id"
    assert sugg["status_path_candidates"][0]["path"] == "status"
    ev_sugg = sugg["evidence_mapping_candidates"][0]
    assert ev_sugg["items"] == "steps"
    assert ev_sugg["provenance"] == "target_reported"
    assert ev_sugg["execution_verified"] is False
    assert ev_sugg["suggested_mapping"]["action"] == "action"
    assert ev_sugg["suggested_mapping"]["arguments"] == "action_input"

    # 9. HTTP 200 with WRONG text_path -> NOT falsely marked verified!
    res_bad_path, _ = catalog.probe_candidate(_mp(text_path="nonexistent.field"))
    assert res_bad_path.http_status == 200
    assert res_bad_path.connection_status == "incompatible"
    assert res_bad_path.verification_state == "response_mapping_unresolved"
    assert res_bad_path.runtime_protocol_compatible is False

    # 10. HTTP 200 with CORRECT nested text_path -> connection_verified, while preserving
    #     unresolved status completion semantics (response_complete=None)!
    res_good, _ = catalog.probe_candidate(_mp(text_path="data.result.text"))
    assert res_good.connection_status == "succeeded"
    assert res_good.runtime_protocol_compatible is True
    assert res_good.verification_state == "connection_verified"
    assert res_good.mapping_diagnostics["response_complete"] is None
    assert res_good.mapping_diagnostics["completeness_unresolved"] is True
    assert res_good.mapping_diagnostics["configured_status_path"] == "status"
    assert "SUPER_SECRET_DIAG_TOKEN_999" not in json.dumps(res_good.model_dump())


# ---------------------------------------------------------------------------
# C. Unified Launcher Credential Forwarding Regression (F-04)
# ---------------------------------------------------------------------------


def test_f04_launcher_forwards_only_registered_target_credentials_to_workflow(tmp_path, monkeypatch):
    """Registered _TOKEN/_API_KEY/_SECRET/custom target creds reach workflow.api ONLY; unregistered secrets dropped everywhere."""
    import start_secagent_local as launcher

    catalog_file = tmp_path / "operator-catalog.json"
    catalog_file.write_text(
        json.dumps({
            "catalog_schema_version": "1.0.0",
            "policy_ref": "g10-launcher-v1",
            "credential_aliases": {
                "a_tok": "LAB_TARGET_TOKEN",
                "a_key": "LAB_TARGET_API_KEY",
                "a_sec": "LAB_TARGET_SECRET",
                "a_custom": "LAB_CUSTOM_BEARER_CRED",
            },
            "targets": [],
        }),
        encoding="utf-8",
    )

    monkeypatch.setenv("LAB_TARGET_TOKEN", "SYNTH_TOK_111")
    monkeypatch.setenv("LAB_TARGET_API_KEY", "SYNTH_KEY_222")
    monkeypatch.setenv("LAB_TARGET_SECRET", "SYNTH_SEC_333")
    monkeypatch.setenv("LAB_CUSTOM_BEARER_CRED", "SYNTH_CUSTOM_444")
    monkeypatch.setenv("UNREGISTERED_API_KEY", "MUST_NOT_FORWARD_1")
    monkeypatch.setenv("UNREGISTERED_TOKEN", "MUST_NOT_FORWARD_2")
    monkeypatch.setenv("UNREGISTERED_SECRET", "MUST_NOT_FORWARD_3")

    monkeypatch.setattr(launcher, "local_data_dir", lambda _: tmp_path)
    monkeypatch.setattr(launcher, "reporting_manifest", lambda _: tmp_path / "manifest.json")
    monkeypatch.setattr(launcher, "available_port", lambda preferred, _: preferred)
    monkeypatch.setattr(launcher, "ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "node")

    calls: list[tuple[list[str], dict[str, str]]] = []

    class FakeProc:
        def poll(self):
            return 0
        def wait(self, **_kwargs):
            return 0

    monkeypatch.setattr(
        launcher.subprocess,
        "Popen",
        lambda cmd, **kw: calls.append((cmd, dict(kw["env"]))) or FakeProc(),
    )

    assert launcher.main(["--no-browser", "--catalog", str(catalog_file)]) == 2

    wf_cmd, wf_env = next((cmd, env) for cmd, env in calls if "workflow.api" in cmd)
    rep_env = next(env for cmd, env in calls if "reporting.api" in cmd)
    fe_env = next(env for cmd, env in calls if any("vite.js" in str(a) for a in cmd))

    assert "--catalog" in wf_cmd and str(catalog_file) in wf_cmd

    # All 4 registered target credentials forwarded ONLY to workflow.api!
    assert wf_env["LAB_TARGET_TOKEN"] == "SYNTH_TOK_111"
    assert wf_env["LAB_TARGET_API_KEY"] == "SYNTH_KEY_222"
    assert wf_env["LAB_TARGET_SECRET"] == "SYNTH_SEC_333"
    assert wf_env["LAB_CUSTOM_BEARER_CRED"] == "SYNTH_CUSTOM_444"

    # NEVER leaked to reporting or frontend (including custom-named non-suffix var)!
    for other_env in (rep_env, fe_env):
        for name in ("LAB_TARGET_TOKEN", "LAB_TARGET_API_KEY", "LAB_TARGET_SECRET", "LAB_CUSTOM_BEARER_CRED"):
            assert name not in other_env

    # Unregistered secrets NEVER forwarded to ANY process!
    for _cmd, env in calls:
        for bad in ("UNREGISTERED_API_KEY", "UNREGISTERED_TOKEN", "UNREGISTERED_SECRET"):
            assert bad not in env


# ---------------------------------------------------------------------------
# D. Response Shape Inspector & Completeness Integrity (F-10, F-11)
# ---------------------------------------------------------------------------


def test_response_inspector_empty_array_ambiguity_and_completeness_integrity():
    # 1. Empty array must NEVER fabricate item field mappings.
    diag_empty = inspect_http_response_shape(
        {"answer": "Done", "status": "completed", "steps": []},
        {"text_path": "answer", "status_path": "status"},
        text_extracted=True,
        response_complete=None,
    )
    ev = diag_empty["suggestions"]["evidence_mapping_candidates"][0]
    assert ev["items"] == "steps"
    assert ev["items_observed"] == 0
    assert ev["item_fields_observed"] is False
    assert ev["suggested_mapping"] == {"items": "steps"}
    assert ev["provenance"] == "target_reported"
    assert ev["execution_verified"] is False
    # Completeness stays unresolved; status_path is NEVER dropped!
    assert diag_empty["configured_status_path"] == "status"
    assert diag_empty["response_complete"] is None
    assert diag_empty["completeness_unresolved"] is True
    assert any("semantic Judge evaluation will remain gated" in m for m in diag_empty["evaluation_readiness_limitations"])

    # 2. Ambiguous non-priority string fields must be marked ambiguous.
    diag_ambig = inspect_http_response_shape(
        {"alpha_note": "one", "beta_note": "two"},
        {"text_path": ""},
        text_extracted=False,
        response_complete=None,
    )
    assert diag_ambig["suggestions"]["text_path_ambiguous"] is True
    assert all(c["ambiguous"] is True for c in diag_ambig["suggestions"]["text_path_candidates"])


# ---------------------------------------------------------------------------
# F. End-to-End API Workflow Fixtures (Scenarios A, B, C, D + Stale Verification)
# ---------------------------------------------------------------------------


def test_e2e_discovery_to_save_and_probe_across_scenarios_b_c_d_and_stale_invalidation(tmp_path, monkeypatch):
    """Exercise full production HTTP routes for Scenario B (authenticated REST), Scenario C (nested JSON), Scenario D (missing OpenAPI)."""
    monkeypatch.setenv("SYNTH_E2E_TOKEN", "E2E_BEARER_SECRET_777")
    doc_b = _agent_runs_openapi_doc()
    doc_c = _nested_execute_openapi_doc()

    def router_handler(req: httpx.Request):
        host_port = f"{req.url.host}:{req.url.port}"
        if req.method == "GET":
            if host_port == "127.0.0.1:7004" and req.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "default"}]})
            if host_port == "127.0.0.1:8000" and req.url.path == "/openapi.json":
                return httpx.Response(200, json=doc_b)
            if host_port == "127.0.0.1:9200" and req.url.path == "/openapi.json":
                return httpx.Response(200, json=doc_c)
            return httpx.Response(404)
        # POST live probe responses
        if host_port == "127.0.0.1:7004" and req.url.path == "/v1/chat/completions":
            return httpx.Response(200, json={"choices": [{"message": {"content": "ready"}, "finish_reason": "stop"}]})
        if host_port == "127.0.0.1:8000" and req.url.path == "/api/agent/runs":
            if req.headers.get("authorization") != "Bearer E2E_BEARER_SECRET_777":
                return httpx.Response(401, json={"detail": "Unauthorized"})
            body = json.loads(req.content)
            assert "defense_level" not in body  # Omitted by default!
            return httpx.Response(
                200,
                json={
                    "run_id": "run-e2e-1",
                    "status": "completed",
                    "answer": f"Executed goal for {body['lab_id']}",
                    "steps": [{"seq": 0, "action": "lookup", "action_input": {"k": 1}, "decision": "allow", "observation": "ok"}],
                },
            )
        if host_port == "127.0.0.1:9200" and req.url.path == "/v2/execute":
            body = json.loads(req.content)
            assert body["workspace"] == "test-workspace"
            assert isinstance(body["task"]["query"], str)
            return httpx.Response(200, json={"data": {"result": {"text": "Example response"}}})
        return httpx.Response(404)

    transport = httpx.MockTransport(router_handler)
    previously_saved = [{
        "id": "preexisting-dvaa-chat",
        "name": "Previously Saved Chat",
        "platform_id": "dvaa",
        "platform_name": "DVAA",
        "reviewed": False,
        "protocol": "openai-chat",
        "endpoint": "http://127.0.0.1:7015/v1/chat/completions",
        "models": ["researchbot"],
        "default_model": "researchbot",
        "timeout_min": 1,
        "timeout_max": 60,
        "timeout_default": 30,
        "credential_alias": None,
    }]
    catalog, gen_service, client, headers = _setup_api(
        tmp_path,
        credential_aliases={"e2e_bearer": "SYNTH_E2E_TOKEN"},
        discovery_transport=transport,
        probe_transport=transport,
        seed_targets=previously_saved,
    )

    # Verify /api/testing/targets and /api/testing/managed-targets expose registered aliases + availability (F-06)
    # and preserve previously saved Target profiles!
    t_resp = client.get("/api/testing/targets", base_url=BASE)
    assert t_resp.status_code == 200
    assert any(t["id"] == "preexisting-dvaa-chat" for t in t_resp.json["targets"])
    assert t_resp.json["credential_aliases"] == ["e2e_bearer"]
    assert t_resp.json["credential_alias_availability"] == {"e2e_bearer": "available"}
    mt_resp = client.get("/api/testing/managed-targets", base_url=BASE, headers=headers)
    assert mt_resp.status_code == 200
    assert mt_resp.json["credential_aliases"] == ["e2e_bearer"]
    assert mt_resp.json["credential_alias_availability"] == {"e2e_bearer": "available"}

    # --- Scenario A: OpenAI-compatible fixture (DVAA CodeBot shape) ---
    disc_a = client.post(
        "/api/testing/discoveries",
        base_url=BASE,
        json={"url": "http://127.0.0.1:7004/v1/chat/completions", "authorization_confirmed": True},
        headers=headers,
    )
    assert disc_a.status_code == 200
    d_a = disc_a.json
    assert d_a["proposed_profile"]["protocol"] == "openai-chat"
    assert d_a["proposed_profile"]["model"] == "default"
    probe_a = client.post(
        "/api/testing/discovery-probes",
        base_url=BASE,
        json={"discovery_id": d_a["discovery_id"], "profile": d_a["proposed_profile"], "authorization_confirmed": True},
        headers=headers,
    )
    assert probe_a.status_code == 200
    assert probe_a.json["connection_status"] == "succeeded"
    assert probe_a.json["reason"] == "openai_chat_response"
    assert client.post(
        "/api/testing/managed-targets/create",
        base_url=BASE,
        json={"profile": d_a["proposed_profile"], "discovery_id": d_a["discovery_id"]},
        headers=headers,
    ).status_code == 200

    # --- Scenario B: Authenticated REST /api/agent/runs ---
    disc_b = client.post(
        "/api/testing/discoveries",
        base_url=BASE,
        json={"url": "http://127.0.0.1:8000/api/agent/runs", "authorization_confirmed": True},
        headers=headers,
    )
    assert disc_b.status_code == 200
    d_b = disc_b.json
    assert d_b["proposed_profile"]["endpoint"] == "http://127.0.0.1:8000/api/agent/runs"
    assert d_b["proposed_profile"]["model"] is None

    # Resolve lab_id, select alias, set 300s timeout, run authorized discovery probe.
    prof_b = {
        **d_b["proposed_profile"],
        "credential_alias": "e2e_bearer",
        "timeout_seconds": 300,
        "http_config": {
            **d_b["proposed_profile"]["http_config"],
            "body_template": {"lab_id": "asi02-1", "goal": "{{input}}"},
        },
    }
    # Missing authorization_confirmed rejected (400).
    assert client.post(
        "/api/testing/discovery-probes",
        base_url=BASE,
        json={"discovery_id": d_b["discovery_id"], "profile": prof_b, "authorization_confirmed": False},
        headers=headers,
    ).status_code == 400

    probe_b = client.post(
        "/api/testing/discovery-probes",
        base_url=BASE,
        json={"discovery_id": d_b["discovery_id"], "profile": prof_b, "authorization_confirmed": True},
        headers=headers,
    )
    assert probe_b.status_code == 200
    assert probe_b.json["connection_status"] == "succeeded"
    assert probe_b.json["extracted_output"] == "Executed goal for asi02-1"
    assert probe_b.json["mapping_diagnostics"]["completeness_unresolved"] is True
    assert "E2E_BEARER_SECRET_777" not in json.dumps(probe_b.json)

    # Save -> Review -> Saved Connection Check -> Verify Stale Invalidation on Material Edit!
    saved_b = client.post(
        "/api/testing/managed-targets/create",
        base_url=BASE,
        json={"profile": prof_b, "discovery_id": d_b["discovery_id"]},
        headers=headers,
    )
    assert saved_b.status_code == 200
    row_b = saved_b.json["profile"]
    assert row_b["timeout_default"] == 300
    assert row_b["default_model"] == ""
    assert row_b["connection_probe"]["status"] == "requires_confirmation"

    conn_b = client.post(
        "/api/testing/connection-checks",
        base_url=BASE,
        json={
            "target_id": row_b["id"],
            "profile_revision": row_b["profile_revision"],
            "policy_ref": row_b["policy_ref"],
            "endpoint": row_b["endpoint"],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert conn_b.status_code == 200
    assert conn_b.json["connection_status"] == "succeeded"

    # Verify target shows connection_verification compatible, then becomes stale on material change!
    listed = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    b_listed = next(t for t in listed if t["id"] == row_b["id"])
    assert b_listed["connection_verification"]["status"] == "compatible"

    edited_prof_b = {
        **prof_b,
        "http_config": {
            **prof_b["http_config"],
            "body_template": {"lab_id": "asi02-2", "goal": "{{input}}"},
        },
    }
    upd_b = client.post(
        "/api/testing/managed-targets/update",
        base_url=BASE,
        json={"profile": edited_prof_b, "expected_profile_revision": row_b["profile_revision"]},
        headers=headers,
    )
    assert upd_b.status_code == 200
    listed_after = client.get("/api/testing/targets", base_url=BASE).json["targets"]
    b_after = next(t for t in listed_after if t["id"] == row_b["id"])
    assert b_after["connection_verification"]["status"] == "stale"

    # --- Scenario C: Unrelated nested JSON /v2/execute ---
    disc_c = client.post(
        "/api/testing/discoveries",
        base_url=BASE,
        json={"url": "http://127.0.0.1:9200/v2/execute", "authorization_confirmed": True},
        headers=headers,
    )
    assert disc_c.status_code == 200
    d_c = disc_c.json
    assert d_c["exact_match_path"] == "/v2/execute"
    assert d_c["proposed_profile"]["http_config"]["body_template"] == {
        "workspace": "<REQUIRED:workspace>",
        "task": {"query": "{{input}}"},
    }
    assert d_c["proposed_profile"]["http_config"]["response"]["text_path"] == "data.result.text"

    prof_c = {
        **d_c["proposed_profile"],
        "http_config": {
            **d_c["proposed_profile"]["http_config"],
            "body_template": {"workspace": "test-workspace", "task": {"query": "{{input}}"}},
        },
    }
    probe_c = client.post(
        "/api/testing/discovery-probes",
        base_url=BASE,
        json={"discovery_id": d_c["discovery_id"], "profile": prof_c, "authorization_confirmed": True},
        headers=headers,
    )
    assert probe_c.status_code == 200
    assert probe_c.json["connection_status"] == "succeeded"
    assert probe_c.json["extracted_output"] == "Example response"
    assert client.post(
        "/api/testing/managed-targets/create",
        base_url=BASE,
        json={"profile": prof_c, "discovery_id": d_c["discovery_id"]},
        headers=headers,
    ).status_code == 200

    # --- Scenario D: Incomplete / Missing OpenAPI -> clean manual fallback ---
    disc_d = client.post(
        "/api/testing/discoveries",
        base_url=BASE,
        json={"url": "http://127.0.0.1:9300/api/mystery", "authorization_confirmed": True},
        headers=headers,
    )
    assert disc_d.status_code == 200
    assert disc_d.json["status"] == "manual_configuration_required"
    assert disc_d.json["configuration_readiness"] == "manual_configuration_required"
    assert disc_d.json["proposed_profile"] is None


# ---------------------------------------------------------------------------
# R-01, R-02, R-03 Bounded Acceptance Correction Regression Tests
# ---------------------------------------------------------------------------


def test_r01_additive_credential_alias_sync_preserves_existing_targets_reviews_and_backups(tmp_path):
    """R-01: Existing managed catalog fails closed without opt-in, safely merges additive aliases with atomic backup on opt-in, and rejects removals/rebinds/policy drift."""
    from workflow.catalog import CatalogError
    from workflow.management import ManagedProfile, ReviewProfile, SaveProfile

    data_dir = tmp_path / "existing-managed-data"
    initial_seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "local-lab-offline-review-v1",
        "credential_aliases": {"existing_alias": "EXISTING_ENV_TOKEN"},
        "targets": [],
    })
    cat = ManagedTargetCatalog(initial_seed, data_dir, local_single_user=True)
    saved = cat.save_profile(
        SaveProfile(
            profile=ManagedProfile(
                id="existing-chat-bot",
                name="Existing Chat Bot",
                platform_id="dvaa",
                platform_name="DVAA",
                endpoint="http://127.0.0.1:7004/v1/chat/completions",
                protocol="openai-chat",
                model="default",
                timeout_seconds=30,
            )
        )
    )
    reviewed = cat.review_profile(
        ReviewProfile(
            target_id=saved["id"],
            profile_revision=saved["profile_revision"],
            policy_ref=saved["policy_ref"],
            endpoint=saved["endpoint"],
            protocol=saved["protocol"],
            model=saved["default_model"],
            capabilities=["chat"],
            authorization_confirmed=True,
        )
    )
    original_rev = reviewed["profile_revision"]
    assert reviewed["authorization_status"] == "reviewed_for_offline_configuration"

    # Adding a new synthetic alias without explicit opt-in MUST still fail closed!
    additive_seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "local-lab-offline-review-v1",
        "credential_aliases": {
            "existing_alias": "EXISTING_ENV_TOKEN",
            "new_lab_bearer": "SYNTH_NEW_LAB_TOKEN",
        },
        "targets": [],
    })
    with pytest.raises(CatalogError):
        ManagedTargetCatalog(additive_seed, data_dir, local_single_user=True)

    # Removing or rebinding an existing alias MUST fail closed even with allow_additive_credential_aliases=True!
    removed_seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "local-lab-offline-review-v1",
        "credential_aliases": {"new_lab_bearer": "SYNTH_NEW_LAB_TOKEN"},
        "targets": [],
    })
    with pytest.raises(CatalogError):
        ManagedTargetCatalog(removed_seed, data_dir, local_single_user=True, allow_additive_credential_aliases=True)

    rebound_seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "local-lab-offline-review-v1",
        "credential_aliases": {"existing_alias": "DIFFERENT_ENV_TOKEN"},
        "targets": [],
    })
    with pytest.raises(CatalogError):
        ManagedTargetCatalog(rebound_seed, data_dir, local_single_user=True, allow_additive_credential_aliases=True)

    # Changing policy_ref MUST fail closed even with allow_additive_credential_aliases=True!
    bad_policy_seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "different-policy-v2",
        "credential_aliases": additive_seed.credential_aliases,
        "targets": [],
    })
    with pytest.raises(CatalogError):
        ManagedTargetCatalog(bad_policy_seed, data_dir, local_single_user=True, allow_additive_credential_aliases=True)

    # Explicit additive sync succeeds, creates an atomic backup, preserves existing target + revision + review!
    synced = ManagedTargetCatalog(
        additive_seed, data_dir, local_single_user=True, allow_additive_credential_aliases=True
    )
    backups = list(data_dir.glob("target-catalog.credential-aliases-*.backup.json"))
    assert len(backups) == 1
    assert set(synced._config.credential_aliases.keys()) == {"existing_alias", "new_lab_bearer"}
    targets_after = synced.public_targets()
    assert len(targets_after) == 1
    assert targets_after[0]["id"] == "existing-chat-bot"
    assert targets_after[0]["profile_revision"] == original_rev
    assert targets_after[0]["authorization_status"] == "reviewed_for_offline_configuration"

    # Subsequent normal startup WITHOUT allow_additive_credential_aliases succeeds cleanly!
    reloaded = ManagedTargetCatalog(additive_seed, data_dir, local_single_user=True)
    assert reloaded.public_targets()[0]["profile_revision"] == original_rev
    assert reloaded.public_targets()[0]["authorization_status"] == "reviewed_for_offline_configuration"
    assert "new_lab_bearer" in reloaded._config.credential_aliases

    # Verify unified launcher forwards --sync-credential-aliases cleanly to workflow.api!
    import start_secagent_local as launcher
    cat_file = tmp_path / "sync-catalog.json"
    cat_file.write_text(json.dumps(additive_seed.model_dump(mode="json")), encoding="utf-8")
    calls: list[list[str]] = []

    class FakeProc:
        def poll(self):
            return 0
        def wait(self, **_kwargs):
            return 0

    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(launcher, "local_data_dir", lambda _: tmp_path / "launch-data")
        mp.setattr(launcher, "reporting_manifest", lambda _: tmp_path / "launch-data" / "manifest.json")
        mp.setattr(launcher, "available_port", lambda preferred, _: preferred)
        mp.setattr(launcher, "ready", lambda *_args, **_kwargs: True)
        mp.setattr(launcher.shutil, "which", lambda _: "node")
        mp.setattr(launcher.subprocess, "Popen", lambda cmd, **kw: calls.append(list(cmd)) or FakeProc())
        assert launcher.main(["--no-browser", "--catalog", str(cat_file), "--sync-credential-aliases"]) == 2
        wf_cmd = next(cmd for cmd in calls if "workflow.api" in cmd)
        assert "--sync-credential-aliases" in wf_cmd
    finally:
        mp.undo()


def test_r02_complete_diagnostic_redaction_across_all_response_fields_and_mapping_diagnostics(tmp_path, monkeypatch):
    """R-02: Synthetic secrets appearing in run_id, status, answer, nested keys, steps, and error messages must never leak anywhere in ConnectionCheckResult."""
    synth_token = "SYNTH_R02_SECRET_XYZ789"
    synth_sk = "sk-synthR02leakKey987654"
    synth_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature12345"
    monkeypatch.setenv("G10_R02_TOKEN", f"Bearer {synth_token}")

    def leaky_handler(req: httpx.Request):
        return httpx.Response(
            200,
            json={
                "run_id": f"corr-{synth_token}",
                "status": f"done_{synth_token}",
                "answer": f"Output with Bearer {synth_token} and {synth_sk} and {synth_jwt}",
                f"key_{synth_token}": "echoed_in_key",
                "steps": [
                    {
                        "seq": 1,
                        "action": "run_tool",
                        f"arg_{synth_token}": {"secret": synth_token},
                        "observation": f"Bearer {synth_token}",
                    }
                ],
            },
        )

    seed = CatalogConfig.model_validate({
        "catalog_schema_version": "1.0.0",
        "policy_ref": "r02-policy-v1",
        "credential_aliases": {"r02_alias": "G10_R02_TOKEN"},
        "targets": [],
    })
    catalog = ManagedTargetCatalog(seed, tmp_path / "data", probe_transport=httpx.MockTransport(leaky_handler))
    from workflow.management import ManagedProfile

    mp = ManagedProfile.model_validate({
        "id": "r02-http",
        "name": "R02 HTTP",
        "platform_id": "lab",
        "platform_name": "Lab",
        "endpoint": "http://127.0.0.1:8000/api/agent/runs",
        "protocol": "http-json",
        "model": None,
        "timeout_seconds": 30,
        "credential_alias": "r02_alias",
        "http_config": {
            "method": "POST",
            "body_template": {"goal": "{{input}}"},
            "headers": {},
            "response": {
                "text_path": "answer",
                "correlation_id_path": "run_id",
                "status_path": "status",
            },
        },
    })
    result, status = catalog.probe_candidate(mp)
    assert status == 200
    assert result.connection_status == "succeeded"

    serialized = json.dumps(result.model_dump())
    for leaked in (synth_token, synth_sk, synth_jwt):
        assert leaked not in serialized

    # Verify structural mapping diagnostics remain intact and completeness semantics untouched!
    md = result.mapping_diagnostics
    assert md is not None
    assert md["configured_text_path"] == "answer"
    assert md["configured_status_path"] == "status"
    assert md["response_complete"] is None
    assert md["completeness_unresolved"] is True
    assert "[REDACTED]" in (md["observed_correlation_id"] or "")
    assert "[REDACTED]" in (md["observed_status_value"] or "")
    assert md["suggestions"]["status_path_candidates"][0]["path"] == "status"
    assert "[REDACTED]" in md["suggestions"]["status_path_candidates"][0]["observed_value"]


def test_r03_http_json_connection_check_requires_per_probe_authorization_even_when_reviewed(tmp_path):
    """R-03: Reviewed http-json targets STILL require explicit authorization_confirmed=True and exact endpoint on every probe; DVAA/MCP remain compatible."""
    seen: list[dict[str, Any]] = []

    def handler(req: httpx.Request):
        seen.append({"url": str(req.url), "body": json.loads(req.content)})
        if req.url.path == "/v1/chat/completions":
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
        return httpx.Response(200, json={"answer": "probe ok"})

    transport = httpx.MockTransport(handler)
    for local_mode in (True, False):
        seed = CatalogConfig.model_validate({
            "catalog_schema_version": "1.0.0",
            "policy_ref": "r03-policy-v1",
            "credential_aliases": {},
            "targets": [],
        })
        cat = ManagedTargetCatalog(
            seed,
            tmp_path / f"data-{local_mode}",
            probe_transport=transport,
            local_single_user=local_mode,
        )
        app = create_app(cat, operator_secret=SECRET, local_single_user=local_mode)
        client = app.test_client()
        nonce = client.get("/api/testing/health", base_url=BASE).json["validation_nonce"]
        headers = {"Origin": BASE, "X-SecAgent-Validation": nonce, "X-SecAgent-Operator": SECRET}

        created = client.post(
            "/api/testing/managed-targets/create",
            base_url=BASE,
            headers=headers,
            json={
                "profile": {
                    "id": "reviewed-http-target",
                    "name": "Reviewed HTTP Target",
                    "platform_id": "lab",
                    "platform_name": "Lab",
                    "endpoint": "http://127.0.0.1:8000/api/agent/runs",
                    "protocol": "http-json",
                    "model": None,
                    "timeout_seconds": 30,
                    "http_config": {
                        "method": "POST",
                        "body_template": {"goal": "{{input}}"},
                        "headers": {},
                        "response": {"text_path": "answer"},
                    },
                }
            },
        ).json["profile"]
        rev_resp = client.post(
            "/api/testing/managed-targets/review",
            base_url=BASE,
            headers=headers,
            json={
                "target_id": created["id"],
                "profile_revision": created["profile_revision"],
                "policy_ref": created["policy_ref"],
                "endpoint": created["endpoint"],
                "protocol": "http-json",
                "model": None,
                "capabilities": ["http_json"],
                "authorization_confirmed": True,
            },
        )
        assert rev_resp.status_code == 200
        seen_before = len(seen)

        base_sel = {
            "target_id": created["id"],
            "profile_revision": created["profile_revision"],
            "policy_ref": created["policy_ref"],
        }
        # 1. Missing authorization_confirmed & endpoint -> REJECTED (403), 0 requests!
        r_no_auth = client.post("/api/testing/connection-checks", base_url=BASE, headers=headers, json=base_sel)
        assert r_no_auth.status_code == 403
        assert len(seen) == seen_before

        # 2. Wrong endpoint -> REJECTED (403), 0 requests!
        r_wrong_ep = client.post(
            "/api/testing/connection-checks",
            base_url=BASE,
            headers=headers,
            json=base_sel | {"endpoint": "http://127.0.0.1:8000/api/other", "authorization_confirmed": True},
        )
        assert r_wrong_ep.status_code == 403
        assert len(seen) == seen_before

        # 3. Explicit authorization_confirmed=True + exact endpoint + normalized sample_input -> SUCCEEDS (1 request)!
        r_ok = client.post(
            "/api/testing/connection-checks",
            base_url=BASE,
            headers=headers,
            json=base_sel | {
                "endpoint": created["endpoint"],
                "authorization_confirmed": True,
                "sample_input": "  custom probe text  ",
            },
        )
        assert r_ok.status_code == 200
        assert r_ok.json["connection_status"] == "succeeded"
        assert r_ok.json["target_request_count"] == 1
        assert len(seen) == seen_before + 1
        assert seen[-1]["body"] == {"goal": "custom probe text"}
