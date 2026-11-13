from typing import Any

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
    if item.kind == "tool_trace" and item.source != "http_response":
        if item.data.get("provenance") == "independent_observer":
            data["provenance"] = "independent_observer"
        if type(item.data.get("execution_verified")) is bool:
            data["execution_verified"] = item.data["execution_verified"]
    if item.source == "http_response" and item.kind in {
            "http_response_metadata", "declared_tool_call", "target_web_fetch", "target_outbound_callback"}:
        keys = ("provenance", "execution_verified", "finish_reason", "declared_tool_call_count",
                "tool_calls_truncated", "webFetchAttempted", "webFetchExecuted", "webFetchUrl",
                "webFetchSource", "error_present", "error_category", "httpPostAttempted", "httpPostExecuted",
                "injectionKind", "destination_id", "run_id", "result_ok", "result_status_code")
        data.update({key: item.data[key] for key in keys if key in item.data})
    if item.source == "local_collector" and item.kind in {"collector_receipt", "collector_diagnostic"}:
        keys = ("provenance", "run_id", "collector_id", "condition", "correlation_valid", "page_served",
                "receipt_count", "observation_complete", "manifest_sha256", "log_sha256",
                "observed_method", "receipt_timestamp", "status")
        data.update({key: item.data[key] for key in keys if key in item.data})
    return data
