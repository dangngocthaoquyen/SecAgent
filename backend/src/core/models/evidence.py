from typing import Any
import re

from pydantic import BaseModel, ConfigDict, Field

class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1)
    source: str = Field(min_length=1)

    name: str | None = None
    success: bool | None = None

    data: dict[str, Any] = Field(default_factory=dict)
    reference: str | None = None


def public_evidence_data(item: Evidence) -> dict[str, Any]:
    """One bounded allowlist for Judge requests and saved report copies."""
    data = {key: item.data[key] for key in ("scope", "completeness")
            if isinstance(item.data.get(key), str)}
    correlation = item.data.get("correlation_reference")
    arguments_hash = item.data.get("arguments_sha256")
    if (item.kind == "declared_tool_call" and item.source == "http_response"):
        if item.data.get("observation_scope") == "target_response_tool_declaration":
            data["observation_scope"] = "target_response_tool_declaration"
        if item.data.get("execution_semantics") == "declared_only":
            data["execution_semantics"] = "declared_only"
        if item.data.get("verification_status") == "target_reported_unverified":
            data["verification_status"] = "target_reported_unverified"
        if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
            data["correlation_reference"] = correlation
        if isinstance(arguments_hash, str) and re.fullmatch(r"[a-f0-9]{64}", arguments_hash):
            data["arguments_sha256"] = arguments_hash
    if item.kind == "tool_trace" and item.source != "http_response":
        if item.data.get("provenance") == "independent_observer":
            data["provenance"] = "independent_observer"
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = item.data["execution_verified"]
        if item.source == "local_tool_fixture" and item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
            if item.data.get("observation_scope") == "synthetic_handler_direct_request":
                data["observation_scope"] = "synthetic_handler_direct_request"
            if item.data.get("execution_semantics") in {
                    "simulated_handler_effect", "simulated_handler_invocation"}:
                data["execution_semantics"] = item.data["execution_semantics"]
            if item.data.get("verification_status") in {
                    "verified_simulated_effect", "verified_handler_invocation"}:
                data["verification_status"] = item.data["verification_status"]
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if item.kind in {"tool_request", "target_tool_result"}:
        if item.data.get("provenance") in {"secagent_request", "target_reported"}:
            data["provenance"] = item.data["provenance"]
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = item.data["execution_verified"]
        for key in ("arguments_sha256", "reported_success"):
            value = item.data.get(key)
            if key == "arguments_sha256" and isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value):
                data[key] = value
            elif key == "reported_success" and type(value) is bool:
                data[key] = value
        if ((item.kind == "tool_request" and item.source == "mcp_jsonrpc_adapter") or
                (item.kind == "target_tool_result" and item.source == "mcp_jsonrpc")):
            expected = (("secagent_direct_tool_request", "direct_tool_request", "request_recorded")
                        if item.kind == "tool_request" else
                        ("mcp_target_result", "target_reported_result", "target_reported_unverified"))
            for key, value in zip(("observation_scope", "execution_semantics", "verification_status"), expected):
                if item.data.get(key) == value:
                    data[key] = value
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if item.kind == "tool_call" and item.data.get("provenance") == "independent_observer":
        data["provenance"] = "independent_observer"
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = item.data["execution_verified"]
        for key in ("execution_id", "invocation_id", "arguments_sha256", "effect_sha256", "scope", "completeness"):
            value = item.data.get(key)
            if isinstance(value, str) and len(value) <= 128:
                data[key] = value
        if item.source == "local_tool_fixture" and item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
            if item.data.get("observation_scope") == "synthetic_handler_direct_request":
                data["observation_scope"] = "synthetic_handler_direct_request"
            if item.data.get("execution_semantics") in {
                    "simulated_handler_effect", "simulated_handler_invocation"}:
                data["execution_semantics"] = item.data["execution_semantics"]
            if item.data.get("verification_status") in {
                    "verified_simulated_effect", "verified_handler_invocation"}:
                data["verification_status"] = item.data["verification_status"]
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if item.source == "http_response" and item.kind in {
            "http_response_metadata", "declared_tool_call", "target_web_fetch", "target_outbound_callback"}:
        keys = ("provenance", "execution_verified", "finish_reason", "assistant_content_present", "declared_tool_call_count",
                "tool_calls_truncated", "webFetchAttempted", "webFetchExecuted", "webFetchUrl",
                "webFetchSource", "error_present", "error_category", "httpPostAttempted", "httpPostExecuted",
                "injectionKind", "destination_id", "run_id", "result_ok", "result_status_code")
        data.update({key: item.data[key] for key in keys if key in item.data})
        if (item.kind == "http_response_metadata" and
                item.data.get("observation_scope") == "target_response_tool_declarations"):
            data["observation_scope"] = "target_response_tool_declarations"
            if item.data.get("verification_status") == "target_reported_unverified":
                data["verification_status"] = "target_reported_unverified"
    if item.source == "http_response" and item.kind in {
            "agent_bridge_trace", "agent_bridge_tool_call"}:
        if item.data.get("provenance") == "target_reported":
            data["provenance"] = "target_reported"
        if item.data.get("execution_verified") is False:
            data["execution_verified"] = False
        if item.data.get("trace_completeness") == "partial":
            data["trace_completeness"] = "partial"
        if item.data.get("verification_status") == "provider_reported_unverified":
            data["verification_status"] = "provider_reported_unverified"
        count = item.data.get("tool_call_count")
        if item.kind == "agent_bridge_trace" and type(count) is int and 0 <= count <= 3:
            data["tool_call_count"] = count
        if item.kind == "agent_bridge_tool_call":
            if isinstance(arguments_hash, str) and re.fullmatch(r"[a-f0-9]{64}", arguments_hash):
                data["arguments_sha256"] = arguments_hash
            for key in ("assistant_selected_reported", "mcp_request_dispatched_reported",
                        "mcp_response_present_reported"):
                if type(item.data.get(key)) is bool:
                    data[key] = item.data[key]
    if item.source == "local_collector" and item.kind in {"collector_receipt", "collector_diagnostic"}:
        keys = ("provenance", "run_id", "collector_id", "condition", "correlation_valid", "page_served",
                "receipt_count", "observation_complete", "manifest_sha256", "log_sha256",
                "observed_method", "receipt_timestamp", "status")
        data.update({key: item.data[key] for key in keys if key in item.data})
    if item.source == "instrumented_handler_receipt" and item.kind == "handler_receipt":
        for key in ("testcase_id", "target_id", "handler_status", "provenance",
                    "source_provenance",
                    "trace_completeness", "attribution", "execution_level"):
            value = item.data.get(key)
            if isinstance(value, str) and len(value) <= 128:
                data[key] = value
        for key in ("execution_id", "request_id", "invocation_id",
                    "arguments_sha256", "result_sha256", "receipt_sha256"):
            value = item.data.get(key)
            if isinstance(value, str) and re.fullmatch(
                    r"[a-f0-9]{32}" if key in {"execution_id", "request_id", "invocation_id"}
                    else r"[a-f0-9]{64}", value):
                data[key] = value
        if item.data.get("execution_verified") is False:
            data["execution_verified"] = False
    if item.source in {"asi05_execution_fixture", "asi05_mcp_request_observer",
                       "instrumented_handler_receipt"} and item.kind in {
            "asi05_execution_trace", "asi05_execution_action"}:
        if item.source in {"asi05_mcp_request_observer", "instrumented_handler_receipt"}:
            stamp = item.data.get("observed_at")
            if isinstance(stamp, str) and len(stamp) <= 40:
                data["observed_at"] = stamp
        for key in ("testcase_id", "target_id", "attribution", "evidence_type",
                    "execution_level", "handler_status", "correlation_status",
                    "trace_completeness", "source_provenance"):
            value = item.data.get(key)
            if isinstance(value, str) and len(value) <= 128:
                data[key] = value
        for key in ("execution_id", "invocation_id", "arguments_sha256",
                    "effect_sha256", "trace_sha256", "receipt_sha256"):
            value = item.data.get(key)
            if isinstance(value, str) and re.fullmatch(
                    r"[a-f0-9]{32}" if key in {"execution_id", "invocation_id"}
                    else r"[a-f0-9]{64}", value):
                data[key] = value
        if item.data.get("provenance") == "independent_observer":
            data["provenance"] = "independent_observer"
        elif item.source == "asi05_mcp_request_observer" and item.data.get("provenance") == "secagent_observed_request":
            data["provenance"] = "secagent_observed_request"
        elif item.source == "instrumented_handler_receipt" and item.data.get("provenance") == "instrumented_target_handler":
            data["provenance"] = "instrumented_target_handler"
        if item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
        if type(item.data.get("observed_action_count")) is int and 0 <= item.data["observed_action_count"] <= 32:
            data["observed_action_count"] = item.data["observed_action_count"]
    return data
