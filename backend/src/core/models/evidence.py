from typing import Any, Literal
import re

from pydantic import BaseModel, ConfigDict, Field

CanonicalProvenance = Literal[
    "model_reported",
    "target_reported",
    "adapter_observed",
    "independently_verified",
]

PROVENANCE_RANK: dict[CanonicalProvenance, int] = {
    "model_reported": 1,
    "target_reported": 2,
    "adapter_observed": 3,
    "independently_verified": 4,
}

COLLECTOR_EVIDENCE_SOURCES = frozenset({
    "generic_evidence_collector",
    "http_callback_collector",
    "sandbox_log_collector",
    "file_artifact_collector",
    "custom_audit_log_collector",
    "mcp_receipt_collector",
})

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
        if type(item.data.get("target_reported_success")) is bool:
            data["target_reported_success"] = item.data["target_reported_success"]
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
        if type(item.data.get("target_reported_success")) is bool:
            data["target_reported_success"] = item.data["target_reported_success"]
    if item.source == "mcp_agent_runtime" and item.kind in {
            "agent_tool_intent", "secagent_mcp_request", "target_mcp_response", "rejected_tool_call"}:
        if item.data.get("provenance") in {"model_reported", "secagent_request", "target_reported", "secagent_policy"}:
            data["provenance"] = item.data["provenance"]
        if item.data.get("execution_verified") is False:
            data["execution_verified"] = False
        if type(item.data.get("target_reported_success")) is bool:
            data["target_reported_success"] = item.data["target_reported_success"]
        for key in ("subject", "attribution", "request_status", "response_status", "reason"):
            value = item.data.get(key)
            if isinstance(value, str) and len(value) <= 128:
                data[key] = value
        for key in ("sequence_index", "model_call_index"):
            value = item.data.get(key)
            if type(value) is int and 0 <= value <= 100:
                data[key] = value
        for key in ("execution_id", "run_id", "invocation_id"):
            value = item.data.get(key)
            if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{32}", value):
                data[key] = value
        for key in ("arguments_sha256", "result_sha256"):
            value = item.data.get(key)
            if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value):
                data[key] = value
        call_id = item.data.get("tool_call_id")
        if isinstance(call_id, str) and len(call_id) <= 128:
            data["tool_call_id"] = call_id
        stamp = item.data.get("timestamp")
        if isinstance(stamp, str) and len(stamp) <= 40:
            data["timestamp"] = stamp
    if item.source in {"asi05_execution_fixture", "asi05_mcp_request_observer",
                       "asi05_agent_mcp_observer", "instrumented_handler_receipt"} and item.kind in {
            "asi05_execution_trace", "asi05_execution_action"}:
        if item.source in {"asi05_mcp_request_observer", "asi05_agent_mcp_observer", "instrumented_handler_receipt"}:
            stamp = item.data.get("observed_at")
            if isinstance(stamp, str) and len(stamp) <= 40:
                data["observed_at"] = stamp
        for key in ("testcase_id", "target_id", "attribution", "evidence_type",
                    "execution_level", "handler_status", "correlation_status",
                    "trace_completeness", "request_trace_completeness", "source_provenance"):
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
        elif item.source in {"asi05_mcp_request_observer", "asi05_agent_mcp_observer"} and item.data.get("provenance") == "secagent_observed_request":
            data["provenance"] = "secagent_observed_request"
        elif item.source == "instrumented_handler_receipt" and item.data.get("provenance") == "instrumented_target_handler":
            data["provenance"] = "instrumented_target_handler"
        if item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
        if type(item.data.get("target_reported_success")) is bool:
            data["target_reported_success"] = item.data["target_reported_success"]
        if type(item.data.get("observed_action_count")) is int and 0 <= item.data["observed_action_count"] <= 32:
            data["observed_action_count"] = item.data["observed_action_count"]
        for count_key in ("secagent_rejected_count", "target_rejected_count", "dispatched_action_count"):
            cval = item.data.get(count_key)
            if type(cval) is int and 0 <= cval <= 100:
                data[count_key] = cval
    if item.kind == "model_reported_tool_intent" and item.source == "response_output_dsml":
        data["provenance"] = "model_reported"
        data["execution_verified"] = False
        if isinstance(item.data.get("format"), str) and len(item.data["format"]) <= 64:
            data["format"] = item.data["format"]
        for count_key in ("tag_count", "invoke_count"):
            cval = item.data.get(count_key)
            if type(cval) is int and 0 <= cval <= 200:
                data[count_key] = cval
        tools = item.data.get("invoked_tool_names")
        if isinstance(tools, list):
            data["invoked_tool_names"] = [t for t in tools[:32] if isinstance(t, str) and len(t) <= 128]
    if item.kind == "stored_response" and item.source in {
        "promptfoo_stored_report", "canonical_stored_json", "offline_stored_import", "canonical_stored_jsonl"
    }:
        data["provenance"] = "target_reported"
        data["execution_verified"] = False
        for key in ("finish_reason", "target_model"):
            val = item.data.get(key)
            if isinstance(val, str) and len(val) <= 128:
                data[key] = val
        if type(item.data.get("response_complete")) is bool:
            data["response_complete"] = item.data["response_complete"]
    if item.kind == "collected_evidence" and item.source in COLLECTOR_EVIDENCE_SOURCES:
        prov = item.data.get("provenance")
        if prov in PROVENANCE_RANK:
            data["provenance"] = prov
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = item.data["execution_verified"]
        for key in (
            "collector_id", "collector_kind", "correlation_status", "correlation_mechanism",
            "verification_status", "claimed_action", "observed_action", "timestamp",
            "integrity_reference", "run_id", "case_id", "request_id", "session_id",
        ):
            val = item.data.get(key)
            if isinstance(val, str) and len(val) <= 256:
                data[key] = val
    return data


def canonical_provenance(item: Evidence) -> CanonicalProvenance:
    """Normalize diverse adapter/observer provenance labels to the 4 canonical tiers."""
    raw_prov = item.data.get("provenance")
    if item.data.get("execution_verified") is True or raw_prov in {
        "independent_observer", "independent_local_collector", "independently_verified"
    }:
        return "independently_verified"
    if raw_prov in {
        "adapter_observed", "secagent_request", "secagent_observed_request", "secagent_policy"
    } or item.source in {"mcp_jsonrpc_adapter", "asi05_mcp_request_observer", "asi05_agent_mcp_observer"}:
        return "adapter_observed"
    if raw_prov == "model_reported" or item.kind in {"model_reported_tool_intent", "agent_tool_intent"}:
        return "model_reported"
    return "target_reported"


def classify_observation_evidence(
    evidence: list[Evidence], response_text: str | None = None
) -> dict[str, Any]:
    """Summarize canonical provenance tiers and evidence level without altering verdicts."""
    if not evidence:
        has_resp = isinstance(response_text, str) and bool(response_text.strip())
        return {
            "evidence_level": "response_only" if has_resp else "none",
            "highest_provenance": "none",
            "provenance_tiers": [],
            "verified_execution_present": False,
        }
    tiers = sorted({canonical_provenance(item) for item in evidence}, key=lambda t: PROVENANCE_RANK[t])
    non_wrapper = [item for item in evidence if item.kind not in {"http_response_metadata", "stored_response"}]
    if not non_wrapper:
        return {
            "evidence_level": "response_only",
            "highest_provenance": max(tiers, key=lambda t: PROVENANCE_RANK[t]),
            "provenance_tiers": tiers,
            "verified_execution_present": False,
        }
    non_wrapper_tiers = sorted(
        {canonical_provenance(item) for item in non_wrapper},
        key=lambda t: PROVENANCE_RANK[t],
    )
    highest = max(non_wrapper_tiers, key=lambda t: PROVENANCE_RANK[t])
    level_map: dict[CanonicalProvenance, str] = {
        "independently_verified": "independently_verified_execution",
        "adapter_observed": "adapter_observed_request",
        "target_reported": "target_reported_claim",
        "model_reported": "model_reported_intent",
    }
    return {
        "evidence_level": level_map[highest],
        "highest_provenance": highest,
        "provenance_tiers": tiers,
        "verified_execution_present": highest == "independently_verified",
    }
