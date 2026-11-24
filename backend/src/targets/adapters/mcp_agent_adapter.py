"""Target adapter wrapping Stage 3B McpAgentRuntime into ExecutionResult."""

from __future__ import annotations

from time import perf_counter
from typing import Any

from core.models import ExecutionResult, TargetProfile, TestInput
from targets.adapters.base import BaseTargetAdapter, TargetAdapterError
from targets.runtimes import McpAgentRuntime, McpAgentRuntimeConfig


class McpAgentRuntimeTargetAdapter(BaseTargetAdapter):
    """Execute one bounded MCP Agent prompt run and normalize to ExecutionResult."""

    def __init__(
        self,
        runtime: McpAgentRuntime,
        config: McpAgentRuntimeConfig,
    ) -> None:
        if not isinstance(runtime, McpAgentRuntime):
            raise ValueError("McpAgentRuntimeTargetAdapter requires an McpAgentRuntime instance.")
        if not isinstance(config, McpAgentRuntimeConfig):
            raise ValueError("McpAgentRuntimeTargetAdapter requires an McpAgentRuntimeConfig instance.")
        self._runtime = runtime
        self._config = config
        self.last_runtime_result = None

    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Invoke McpAgentRuntime.run without performing evaluation verdict logic."""
        if (
            target.interface.type != "agent"
            or target.interface.adapter != "mcp_agent_runtime"
            or target.id != self._config.llm_target_id
            or target.interface.config.get("url") != self._config.llm_endpoint
            or target.interface.config.get("mcp_url") != self._config.mcp_endpoint
        ):
            raise TargetAdapterError("Target profile does not match the reviewed MCP Agent binding.")
        if not isinstance(test_input.prompt, str) or not test_input.prompt:
            raise TargetAdapterError("MCP Agent execution requires a non-empty TestInput.prompt.")

        started = perf_counter()
        runtime_result = self._runtime.run(test_input.prompt, self._config)
        duration_ms = max(0.0, (perf_counter() - started) * 1000.0)
        self.last_runtime_result = runtime_result

        events: list[dict[str, Any]] = []
        for ev in runtime_result.events:
            ev_success: bool | None = None
            if ev.kind == "target_mcp_response":
                ev_success = ev.response_status == "ok"
            elif ev.kind == "rejected_tool_call":
                ev_success = False
            events.append({
                "kind": ev.kind,
                "source": "mcp_agent_runtime",
                "name": ev.tool_name,
                "success": ev_success,
                "reference": (
                    f"agent-invocation/{ev.invocation_id}"
                    if ev.invocation_id is not None
                    else f"agent-run/{runtime_result.run_id}/seq/{ev.sequence_index}"
                ),
                "data": {
                    "provenance": ev.provenance,
                    "execution_verified": False,
                    "subject": ev.subject,
                    "attribution": ev.attribution,
                    "execution_id": test_input.id,
                    "run_id": ev.run_id,
                    "sequence_index": ev.sequence_index,
                    "model_call_index": ev.model_call_index,
                    "tool_call_id": ev.tool_call_id,
                    "invocation_id": ev.invocation_id,
                    "arguments_sha256": ev.arguments_sha256,
                    "request_status": ev.request_status,
                    "response_status": ev.response_status,
                    **({"target_reported_success": ev.target_reported_success}
                       if ev.target_reported_success is not None else {}),
                    "result_sha256": ev.result_sha256,
                    "reason": ev.reason,
                    "timestamp": ev.timestamp,
                },
            })

        completed = runtime_result.status == "completed" and runtime_result.response_complete is True
        error_text = None
        if not completed:
            detail = runtime_result.error or runtime_result.completion_status or runtime_result.status
            error_text = f"agent_runtime_{runtime_result.status}:{detail}"

        return ExecutionResult(
            success=completed,
            status_code=200 if completed else None,
            output_text=runtime_result.assistant_text,
            response_complete=True if completed else False,
            raw_output={
                "agent_runtime_result": runtime_result.model_dump(mode="json"),
                "dispatched_tool_arguments": dict(getattr(self._runtime, "last_dispatched_tool_arguments", {})),
            },
            headers={},
            events=events,
            duration_ms=duration_ms,
            error=error_text,
        )
