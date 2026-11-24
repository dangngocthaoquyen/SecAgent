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

# Trusted producer allowlists by evidence contract (never trust unknown sources by denylist absence).
TRUSTED_INDEPENDENT_OBSERVER_SOURCES = frozenset({
    "local_tool_fixture",
    "runtime_trace",
    "adapter",
    "offline-trusted-observer",
})

TRUSTED_LOCAL_COLLECTOR_SOURCES = frozenset({
    "local_collector",
})

INDEPENDENT_PROVENANCE_LABELS = frozenset({
    "independent_observer",
    "independent_local_collector",
    "independently_verified",
})

ADAPTER_REQUEST_SOURCES = frozenset({
    "mcp_jsonrpc_adapter",
    "asi05_mcp_request_observer",
    "asi05_agent_mcp_observer",
})

ADAPTER_REQUEST_PROVENANCE_LABELS = frozenset({
    "secagent_request",
    "secagent_observed_request",
    "secagent_policy",
})

NEGATIVE_CORRELATION_STATUSES = frozenset({
    "uncorrelated",
    "unverified",
    "failed",
    "mismatch",
    "conflicting",
    "invalid",
    "none",
    "missing",
})

NEGATIVE_CORRELATION_STRENGTHS = frozenset({
    "none",
    "weak",
})

BOUNDED_CORRELATION_STRENGTHS = frozenset({
    "none",
    "weak",
    "strong",
})

NEGATIVE_VERIFICATION_STATUSES = frozenset({
    "unverified",
    "not_verified",
    "conflicting",
    "conflicting_execution_metadata",
    "failed",
    "rejected",
    "invalid",
})

NON_EXECUTION_SEMANTICS = frozenset({
    "declared_only",
    "direct_tool_request",
    "target_reported_result",
    "simulated_handler_invocation",
})

BOUNDED_EXECUTION_SEMANTICS = frozenset({
    "declared_only",
    "direct_tool_request",
    "target_reported_result",
    "simulated_handler_invocation",
    "simulated_handler_effect",
    "verified_runtime_effect",
    "executed_action",
})

WRAPPER_EVIDENCE_KINDS = frozenset({
    "http_response_metadata",
    "stored_response",
})

TARGET_CLAIM_EVIDENCE_KINDS = frozenset({
    "declared_tool_call",
    "target_tool_result",
    "target_inline_event",
    "target_web_fetch",
    "target_outbound_callback",
    "agent_bridge_trace",
    "agent_bridge_tool_call",
    "target_mcp_response",
    "handler_receipt",
})


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _has_malformed_verification_metadata(data: dict[str, Any]) -> bool:
    """Return True if any verification/correlation field carries an unsupported non-scalar type."""
    for str_key in (
        "provenance",
        "correlation_status",
        "correlation_strength",
        "verification_status",
        "execution_semantics",
    ):
        val = data.get(str_key)
        if val is not None and not isinstance(val, str):
            return True
    for bool_key in (
        "execution_verified",
        "correlation_valid",
        "executed",
        "effect_verified",
        "effect_observed",
        "page_served",
        "synthetic_mock",
    ):
        val = data.get(bool_key)
        if val is not None and type(val) is not bool:
            return True
    return False


def has_negative_verification_or_correlation(
    data: dict[str, Any], *, require_effect_observed: bool = False
) -> bool:
    """Return True if metadata carries negative, contradictory, or malformed correlation/verification signals."""
    if not isinstance(data, dict):
        return True
    if _has_malformed_verification_metadata(data):
        return True
    if data.get("executed") is False or data.get("effect_verified") is False:
        return True
    if require_effect_observed and data.get("effect_observed") is False:
        return True
    if data.get("correlation_valid") is False:
        return True
    corr_status = _as_str(data.get("correlation_status"))
    if corr_status is not None and corr_status.strip().lower() in NEGATIVE_CORRELATION_STATUSES:
        return True
    corr_strength = _as_str(data.get("correlation_strength"))
    if corr_strength is not None and corr_strength.strip().lower() in NEGATIVE_CORRELATION_STRENGTHS:
        return True
    ver_status = _as_str(data.get("verification_status"))
    if ver_status is not None:
        norm = ver_status.strip().lower()
        if (
            norm in NEGATIVE_VERIFICATION_STATUSES
            or norm.endswith("_unverified")
            or norm.endswith("_not_verified")
            or norm.startswith("conflicting_")
        ):
            return True
    semantics = _as_str(data.get("execution_semantics"))
    if semantics is not None:
        norm_sem = semantics.strip().lower()
        if norm_sem in NON_EXECUTION_SEMANTICS or semantics != semantics.strip():
            return True
    return False


def is_execution_verified(item: "Evidence") -> bool:
    """Centralized allowlist-based execution verification predicate across evidence contracts."""
    if item.kind in WRAPPER_EVIDENCE_KINDS:
        return False
    data = item.data
    if not isinstance(data, dict):
        return False
    if data.get("execution_verified") is not True:
        return False
    # Contract-specific effect_observed check: only file-artifact effect collectors treat
    # effect_observed=False as contradicting verified effect; command/callback logs can verify
    # an executed action that produced no side effect or failed.
    require_effect = item.source == "file_artifact_collector"
    if has_negative_verification_or_correlation(data, require_effect_observed=require_effect):
        return False
    raw_prov = _as_str(data.get("provenance"))
    if raw_prov is None or raw_prov not in INDEPENDENT_PROVENANCE_LABELS:
        return False

    semantics = _as_str(data.get("execution_semantics"))

    # Contract 1: Generic evidence collectors require strong positive correlation.
    if item.kind == "collected_evidence" and item.source in COLLECTOR_EVIDENCE_SOURCES:
        corr_status = _as_str(data.get("correlation_status"))
        corr_strength = _as_str(data.get("correlation_strength"))
        if semantics == "simulated_handler_effect" and data.get("synthetic_mock") is not True:
            return False
        return (
            corr_status in {"matched", "verified"}
            and corr_strength == "strong"
        )

    # Contract 2: Local WebFixture collector receipt requires validated page + callback correlation.
    if item.kind == "collector_receipt" and item.source in TRUSTED_LOCAL_COLLECTOR_SOURCES:
        return (
            raw_prov in {"independent_local_collector", "independently_verified"}
            and data.get("correlation_valid") is True
            and data.get("page_served") is True
        )

    # Contract 3: Trusted independent runtime/tool observers (do not impose collector-specific fields).
    if item.kind in {"tool_call", "tool_trace"} and item.source in TRUSTED_INDEPENDENT_OBSERVER_SOURCES:
        if raw_prov not in {"independent_observer", "independently_verified"}:
            return False
        if semantics == "simulated_handler_effect":
            return (
                data.get("synthetic_mock") is True
                and _as_str(data.get("verification_status")) == "verified_simulated_effect"
            )
        return True

    # Unknown or untrusted producers are never granted verified execution.
    return False


def is_adapter_observed_request(item: "Evidence") -> bool:
    """Return True only when evidence reflects an actual adapter/SecAgent-observed request."""
    if item.kind in WRAPPER_EVIDENCE_KINDS:
        return False
    raw_prov = _as_str(item.data.get("provenance")) if isinstance(item.data, dict) else None
    if item.kind in {"tool_request", "secagent_mcp_request", "rejected_tool_call"} and item.source in {
        "mcp_jsonrpc_adapter",
        "mcp_agent_runtime",
    }:
        return True
    if item.source in ADAPTER_REQUEST_SOURCES:
        return True
    if raw_prov is not None and raw_prov in ADAPTER_REQUEST_PROVENANCE_LABELS and item.source in (
        ADAPTER_REQUEST_SOURCES | {"mcp_agent_runtime"}
    ):
        return True
    return False

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
    if item.kind == "tool_trace" and item.source in TRUSTED_INDEPENDENT_OBSERVER_SOURCES:
        if _as_str(item.data.get("provenance")) == "independent_observer":
            data["provenance"] = "independent_observer"
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = (
                True if is_execution_verified(item) else False
            )
        if item.source == "local_tool_fixture" and item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
            if _as_str(item.data.get("observation_scope")) == "synthetic_handler_direct_request":
                data["observation_scope"] = "synthetic_handler_direct_request"
            sem = _as_str(item.data.get("execution_semantics"))
            if sem in {"simulated_handler_effect", "simulated_handler_invocation"}:
                data["execution_semantics"] = sem
            ver = _as_str(item.data.get("verification_status"))
            if ver in {"verified_simulated_effect", "verified_handler_invocation"}:
                data["verification_status"] = ver
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if item.kind in {"tool_request", "target_tool_result"}:
        prov_tr = _as_str(item.data.get("provenance"))
        if prov_tr in {"secagent_request", "target_reported"}:
            data["provenance"] = prov_tr
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = False
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
                if _as_str(item.data.get(key)) == value:
                    data[key] = value
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if (
        item.kind == "tool_call"
        and item.source in TRUSTED_INDEPENDENT_OBSERVER_SOURCES
        and _as_str(item.data.get("provenance")) == "independent_observer"
    ):
        data["provenance"] = "independent_observer"
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = (
                True if is_execution_verified(item) else False
            )
        for key in ("execution_id", "invocation_id", "arguments_sha256", "effect_sha256", "scope", "completeness"):
            value = item.data.get(key)
            if isinstance(value, str) and len(value) <= 128:
                data[key] = value
        if item.source == "local_tool_fixture" and item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
            if _as_str(item.data.get("observation_scope")) == "synthetic_handler_direct_request":
                data["observation_scope"] = "synthetic_handler_direct_request"
            sem = _as_str(item.data.get("execution_semantics"))
            if sem in {"simulated_handler_effect", "simulated_handler_invocation"}:
                data["execution_semantics"] = sem
            ver = _as_str(item.data.get("verification_status"))
            if ver in {"verified_simulated_effect", "verified_handler_invocation"}:
                data["verification_status"] = ver
            if isinstance(correlation, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", correlation):
                data["correlation_reference"] = correlation
    if item.source == "http_response" and item.kind in {
            "http_response_metadata", "declared_tool_call", "target_web_fetch", "target_outbound_callback"}:
        # HTTP responses are target-reported and never carry verified execution.
        data["provenance"] = "target_reported"
        data["execution_verified"] = False
        keys = ("finish_reason", "assistant_content_present", "declared_tool_call_count",
                "tool_calls_truncated", "webFetchAttempted", "webFetchExecuted", "webFetchUrl",
                "webFetchSource", "error_present", "error_category", "httpPostAttempted", "httpPostExecuted",
                "injectionKind", "destination_id", "run_id", "result_ok", "result_status_code")
        data.update({key: item.data[key] for key in keys if key in item.data})
        ver_status = item.data.get("verification_status")
        if isinstance(ver_status, str) and ver_status.strip() and len(ver_status) <= 128:
            norm_vs = ver_status.strip().lower()
            if (
                norm_vs == "target_reported_unverified"
                or norm_vs in NEGATIVE_VERIFICATION_STATUSES
                or norm_vs.endswith("_unverified")
                or norm_vs.endswith("_not_verified")
                or norm_vs.startswith("conflicting_")
            ):
                data["verification_status"] = ver_status.strip()
        if (item.kind == "http_response_metadata" and
                item.data.get("observation_scope") == "target_response_tool_declarations"):
            data["observation_scope"] = "target_response_tool_declarations"
            if item.data.get("verification_status") == "target_reported_unverified":
                data["verification_status"] = "target_reported_unverified"
    if item.source == "http_response" and item.kind == "target_inline_event":
        data["provenance"] = "target_reported"
        data["execution_verified"] = False
        data["observation_scope"] = "target_response_inline_evidence"
        data["execution_semantics"] = "target_reported_result"
        data["verification_status"] = "target_reported_unverified"
        for key in (
            "target_correlation_id",
            "target_run_status",
            "event_id",
            "action",
            "decision",
            "status",
            "timestamp",
            "observation_type",
            "disclosure_limitation",
        ):
            val = item.data.get(key)
            if isinstance(val, str) and len(val) <= 256:
                data[key] = val
        arg_keys = item.data.get("argument_keys")
        if isinstance(arg_keys, list):
            safe_keys = [k for k in arg_keys[:16] if isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", k)]
            if safe_keys:
                data["argument_keys"] = safe_keys
        for hash_key in ("arguments_sha256", "observation_sha256"):
            val = item.data.get(hash_key)
            if isinstance(val, str) and re.fullmatch(r"[a-f0-9]{64}", val):
                data[hash_key] = val
        for inc_key in ("arguments_hash_incomplete", "observation_hash_incomplete"):
            if item.data.get(inc_key) is True:
                data[inc_key] = True
        fp = item.data.get("event_fingerprint")
        if isinstance(fp, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", fp):
            data["event_fingerprint"] = fp
        if item.data.get("inline_events_truncated") is True:
            data["inline_events_truncated"] = True
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
        corr_strength_lc = _as_str(item.data.get("correlation_strength"))
        if corr_strength_lc is not None and corr_strength_lc in BOUNDED_CORRELATION_STRENGTHS:
            data["correlation_strength"] = corr_strength_lc
        corr_status_lc = _as_str(item.data.get("correlation_status"))
        if corr_status_lc is not None and len(corr_status_lc) <= 64:
            data["correlation_status"] = corr_status_lc
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = True if is_execution_verified(item) else False
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
        prov_mcp = _as_str(item.data.get("provenance"))
        if prov_mcp in {"model_reported", "secagent_request", "target_reported", "secagent_policy"}:
            data["provenance"] = prov_mcp
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
    if item.kind == "model_reported_tool_intent" and item.source in {
        "response_output_dsml",
        "response_output_tool_intent",
    }:
        data["provenance"] = "model_reported"
        data["execution_verified"] = False
        if isinstance(item.data.get("format"), str) and len(item.data["format"]) <= 64:
            data["format"] = item.data["format"]
        formats_list = item.data.get("formats")
        if isinstance(formats_list, list):
            clean_fmts = [f for f in formats_list[:8] if isinstance(f, str) and len(f) <= 64]
            if clean_fmts:
                data["formats"] = clean_fmts
        for str_key, allowed_vals in (
            ("observation_scope", {"model_response_text"}),
            ("execution_semantics", {"model_text_intent"}),
            ("verification_status", {"model_reported_unverified"}),
        ):
            sval = _as_str(item.data.get(str_key))
            if sval is not None and sval in allowed_vals:
                data[str_key] = sval
        for count_key in ("tag_count", "invoke_count", "deduplicated_against_structured_count"):
            cval = item.data.get(count_key)
            if type(cval) is int and 0 <= cval <= 200:
                data[count_key] = cval
        if type(item.data.get("truncated")) is bool:
            data["truncated"] = item.data["truncated"]
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
        prov = _as_str(item.data.get("provenance"))
        corr_st_raw = _as_str(item.data.get("correlation_status"))
        is_neg_corr = (
            corr_st_raw is not None
            and corr_st_raw.strip().lower() in NEGATIVE_CORRELATION_STATUSES
        )
        if prov is not None and prov in PROVENANCE_RANK:
            if prov == "independently_verified" and not is_execution_verified(item):
                data["provenance"] = "target_reported" if is_neg_corr else "adapter_observed"
            else:
                data["provenance"] = prov
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = (
                True if is_execution_verified(item) else False
            )
        corr_strength = _as_str(item.data.get("correlation_strength"))
        if corr_strength is not None and corr_strength in BOUNDED_CORRELATION_STRENGTHS:
            data["correlation_strength"] = corr_strength
        exec_sem = _as_str(item.data.get("execution_semantics"))
        if exec_sem is not None and exec_sem in BOUNDED_EXECUTION_SEMANTICS:
            data["execution_semantics"] = exec_sem
        if item.data.get("synthetic_mock") is True:
            data["synthetic_mock"] = True
        if item.data.get("effect_verified") is False:
            data["effect_verified"] = False
        if item.data.get("correlation_valid") is False:
            data["correlation_valid"] = False
        for key in (
            "collector_id", "collector_kind", "correlation_status", "correlation_mechanism",
            "verification_status", "claimed_action", "observed_action", "timestamp",
            "integrity_reference", "run_id", "case_id", "request_id", "session_id",
            "target_correlation_id", "event_id", "event_fingerprint",
        ):
            val = item.data.get(key)
            if isinstance(val, str) and len(val) <= 256:
                data[key] = val

    # Universal invariant: public_evidence_data must NEVER increase verification trust.
    if not is_execution_verified(item):
        if data.get("execution_verified") is True:
            data["execution_verified"] = False
        if _as_str(data.get("provenance")) == "independently_verified":
            cs = _as_str(item.data.get("correlation_status")) if isinstance(item.data, dict) else None
            neg_cs = cs is not None and cs.strip().lower() in NEGATIVE_CORRELATION_STATUSES
            data["provenance"] = "target_reported" if neg_cs else "adapter_observed"
    return data


def canonical_provenance(item: Evidence) -> CanonicalProvenance:
    """Normalize diverse adapter/observer provenance labels to the 4 canonical tiers."""
    if is_execution_verified(item):
        return "independently_verified"
    if is_adapter_observed_request(item):
        return "adapter_observed"
    raw_prov = _as_str(item.data.get("provenance")) if isinstance(item.data, dict) else None
    corr_status = _as_str(item.data.get("correlation_status")) if isinstance(item.data, dict) else None
    corr_uncorrelated = (
        corr_status is not None and corr_status.strip().lower() in NEGATIVE_CORRELATION_STATUSES
    ) or (isinstance(item.data, dict) and item.data.get("correlation_valid") is False)
    if (
        raw_prov is not None
        and item.source in COLLECTOR_EVIDENCE_SOURCES
        and raw_prov in (INDEPENDENT_PROVENANCE_LABELS | {"adapter_observed"})
        and not corr_uncorrelated
    ):
        return "adapter_observed"
    if (
        raw_prov is not None
        and item.source in (TRUSTED_INDEPENDENT_OBSERVER_SOURCES | TRUSTED_LOCAL_COLLECTOR_SOURCES)
        and raw_prov in (INDEPENDENT_PROVENANCE_LABELS | {"adapter_observed"})
        and not corr_uncorrelated
    ):
        return "adapter_observed"
    if raw_prov == "model_reported" or item.kind in {"model_reported_tool_intent", "agent_tool_intent"}:
        return "model_reported"
    return "target_reported"


def _is_substantive_target_claim(item: Evidence) -> bool:
    if item.kind in TARGET_CLAIM_EVIDENCE_KINDS:
        return True
    if item.kind == "collected_evidence":
        corr_status = item.data.get("correlation_status")
        is_uncorrelated = isinstance(corr_status, str) and corr_status.strip().lower() in NEGATIVE_CORRELATION_STATUSES
        if not is_uncorrelated and item.data.get("provenance") == "target_reported":
            return True
        return False
    # Untrusted/unknown sources claiming tool_call/tool_trace remain unverified claims, not verified execution.
    if item.kind in {"tool_call", "tool_trace"} and item.source not in TRUSTED_INDEPENDENT_OBSERVER_SOURCES:
        return True
    return False


def classify_observation_evidence(
    evidence: list[Evidence], response_text: str | None = None
) -> dict[str, Any]:
    """Summarize canonical provenance tiers and evidence level without altering verdicts."""
    has_resp = isinstance(response_text, str) and bool(response_text.strip())
    if not evidence:
        return {
            "evidence_level": "response_only" if has_resp else "none",
            "highest_provenance": "none",
            "provenance_tiers": [],
            "verified_execution_present": False,
        }
    tiers = sorted({canonical_provenance(item) for item in evidence}, key=lambda t: PROVENANCE_RANK[t])
    non_wrapper = [item for item in evidence if item.kind not in WRAPPER_EVIDENCE_KINDS]
    if not non_wrapper:
        return {
            "evidence_level": "response_only" if has_resp else "none",
            "highest_provenance": max(tiers, key=lambda t: PROVENANCE_RANK[t]),
            "provenance_tiers": tiers,
            "verified_execution_present": False,
        }
    non_wrapper_tiers = sorted(
        {canonical_provenance(item) for item in non_wrapper},
        key=lambda t: PROVENANCE_RANK[t],
    )
    highest = max(non_wrapper_tiers, key=lambda t: PROVENANCE_RANK[t])
    verified_present = any(is_execution_verified(item) for item in non_wrapper)
    if verified_present:
        evidence_level = "independently_verified_execution"
    elif any(is_adapter_observed_request(item) for item in non_wrapper):
        evidence_level = "adapter_observed_request"
    elif any(_is_substantive_target_claim(item) for item in non_wrapper):
        evidence_level = "target_reported_claim"
    elif any(canonical_provenance(item) == "model_reported" for item in non_wrapper):
        evidence_level = "model_reported_intent"
    else:
        # Unverified collector/observer records or zero-receipt fixtures do not imply
        # verified execution or an observed tool request.
        evidence_level = "response_only" if has_resp else "none"
    return {
        "evidence_level": evidence_level,
        "highest_provenance": highest,
        "provenance_tiers": tiers,
        "verified_execution_present": verified_present,
    }
