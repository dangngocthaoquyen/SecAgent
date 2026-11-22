"""Offline evidence boundaries for response, MCP claims and synthetic effects."""

from hashlib import sha256
import json
from uuid import uuid4

import pytest

from core.models import Evidence, ExecutionResult, TargetInterface, TargetProfile
from core.models import TestInput as CoreTestInput
from core.models.evidence import public_evidence_data
from observers import ResponseObserver, ToolActionObserver
from targets.adapters.http_evidence import reported_http_evidence
from targets.adapters.mcp_jsonrpc_adapter import McpJsonRpcTargetAdapter
from tools.http import HttpResponse


def test_fixture_a_textual_tool_tag_remains_response_text_only():
    text = '<tool_call>{"name":"execute","arguments":{"command":"echo demo"}}</tool_call>'
    body = {"choices": [{"finish_reason": "stop", "message": {"content": text}}]}
    events = reported_http_evidence(body)
    observation = ResponseObserver().observe(ExecutionResult(
        success=True, output_text=text, events=events))

    assert observation.response_text == text
    assert [item.kind for item in observation.evidence] == ["http_response_metadata"]
    assert observation.tool_calls == []
    assert not any(item.data.get("execution_verified") is True for item in observation.evidence)


def test_fixture_b_structured_http_call_has_bounded_untrusted_correlation():
    arguments = '{"password":"private-value","command":"echo demo"}'
    call_id = "private-call-identity"
    body = {"choices": [{"finish_reason": "tool_calls", "message": {
        "content": None, "tool_calls": [{"id": call_id, "type": "function",
            "function": {"name": "execute", "arguments": arguments}}]}}]}
    events = reported_http_evidence(body)
    evidence = ResponseObserver().observe(ExecutionResult(
        success=True, events=events, headers={"authorization": "private-header"})).evidence
    declaration = evidence[1]
    projected = public_evidence_data(declaration)

    assert [item.kind for item in evidence] == ["http_response_metadata", "declared_tool_call"]
    assert public_evidence_data(evidence[0])["observation_scope"] == "target_response_tool_declarations"
    assert public_evidence_data(evidence[0])["completeness"] == "complete"
    assert declaration.data["execution_semantics"] == "declared_only"
    assert projected["arguments_sha256"] == sha256(arguments.encode()).hexdigest()
    assert projected["correlation_reference"] == "sha256:" + sha256(
        ("openai-tool-call-id:" + call_id).encode()).hexdigest()
    assert projected["execution_verified"] is False
    assert not {"tool_call", "tool_trace"} & {item.kind for item in evidence}
    serialized = json.dumps([item.model_dump() for item in evidence] + [projected])
    assert not any(secret in serialized for secret in (arguments, "private-value", call_id, "private-header"))


class _McpClient:
    def request(self, **kwargs):
        body = kwargs["json_body"]
        result = {"jsonrpc": "2.0", "id": body["id"], "result": {"content": [
            {"type": "text", "text": '{"success":true,"output":"reported"}'}]}}
        return HttpResponse(status_code=200, headers={"authorization": "private-header"},
                            text=json.dumps(result), json_body=result, duration_ms=1.0)


def _mcp_result():
    target = TargetProfile(id="offline-mcp", name="Offline MCP", target_type="tool_service",
        interface=TargetInterface(type="mcp", adapter="generic_mcp_jsonrpc",
            config={"url": "https://example.invalid/mcp", "request_id": 7}))
    test_input = CoreTestInput(id="fixture-input", parameters={"tool_call": {
        "name": "execute", "arguments": {"token": "private-argument"}}})
    return McpJsonRpcTargetAdapter(_McpClient()).execute(target, test_input)


def test_fixture_c_mcp_success_without_handler_receipt_is_only_target_reported():
    observation = ResponseObserver().observe(_mcp_result())
    request, response = observation.evidence
    projected = [public_evidence_data(item) for item in observation.evidence]

    assert [request.kind, response.kind] == ["tool_request", "target_tool_result"]
    assert projected[0]["execution_semantics"] == "direct_tool_request"
    assert projected[1]["execution_semantics"] == "target_reported_result"
    assert projected[0]["correlation_reference"] == projected[1]["correlation_reference"]
    assert projected[0]["arguments_sha256"] == projected[1]["arguments_sha256"]
    assert projected[1]["reported_success"] is True
    assert projected[1]["execution_verified"] is False
    assert not any(item.kind in {"tool_call", "tool_trace"} for item in observation.evidence)
    assert not any(secret in json.dumps(projected) for secret in ("private-argument", "private-header"))


def _write_synthetic_receipt(root, result, execution_id, *, wrong_hash=False):
    request = result.events[0]
    invocation_id = uuid4().hex
    arguments_hash = request["data"]["arguments_sha256"]
    effect = json.dumps({"handler_invoked": True, "synthetic_mock": True,
        "execution_id": execution_id, "invocation_id": invocation_id,
        "request_id": request["data"]["request_id"], "tool_name": request["name"],
        "arguments_sha256": arguments_hash}, sort_keys=True).encode()
    (root / (execution_id + ".effect.json")).write_bytes(effect)
    receipt = {"execution_id": execution_id, "invocation_id": invocation_id,
        "request_id": request["data"]["request_id"], "tool_name": request["name"],
        "arguments_sha256": "0" * 64 if wrong_hash else arguments_hash,
        "status": "succeeded", "observation_complete": True,
        "provenance": "independent_observer", "effect_identity_required": True,
        "effect_sha256": sha256(effect).hexdigest()}
    (root / (execution_id + ".receipt.json")).write_text(json.dumps(receipt), encoding="utf-8")


def test_fixture_d_correlated_synthetic_handler_is_not_runtime_execution(tmp_path):
    result = _mcp_result()
    execution_id = uuid4().hex
    _write_synthetic_receipt(tmp_path, result, execution_id)
    evidence = ToolActionObserver(tmp_path, execution_id).observe(result).evidence
    handler, trace = evidence[2:]
    projected = [public_evidence_data(item) for item in evidence]

    assert [item.kind for item in evidence] == [
        "tool_request", "target_tool_result", "tool_call", "tool_trace"]
    assert handler.data["execution_verified"] is True  # Existing receipt semantics.
    assert projected[2]["execution_semantics"] == "simulated_handler_effect"
    assert projected[2]["verification_status"] == "verified_simulated_effect"
    assert projected[2]["synthetic_mock"] is True
    assert projected[3]["synthetic_mock"] is True
    assert projected[0]["correlation_reference"] == projected[2]["correlation_reference"]
    assert trace.data["scope"] == "direct_request"
    assert all(item.get("execution_semantics") != "verified_runtime_effect" for item in projected)


def test_fixture_d_wrong_hash_or_run_identity_cannot_join(tmp_path):
    result = _mcp_result()
    execution_id = uuid4().hex
    _write_synthetic_receipt(tmp_path, result, execution_id, wrong_hash=True)
    with pytest.raises(ValueError, match="does not match"):
        ToolActionObserver(tmp_path, execution_id).observe(result)

    # A valid receipt for one run is not evidence for another run.
    other_id = uuid4().hex
    assert [item.kind for item in ToolActionObserver(tmp_path, other_id).observe(result).evidence] == [
        "tool_request", "target_tool_result"]


def test_fixture_e_disconnected_telemetry_does_not_claim_no_action():
    observation = ResponseObserver().observe(ExecutionResult(
        success=True, output_text="No action visible.", events=[]))
    assert observation.evidence == []
    assert "response_complete" not in observation.metadata
    assert "tool_trace" not in observation.metadata
    assert public_evidence_data(Evidence(kind="tool_request", source="legacy")) == {}
