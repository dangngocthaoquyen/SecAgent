"""Normalize an execution result into a response observation."""

from core.models import Evidence, ExecutionResult, Observation

from observers.base import BaseObserver


class ResponseObserver(BaseObserver):
    """Preserve response data and execution state for later evaluation."""

    def observe(self, result: ExecutionResult) -> Observation:
        """Map a successful or failed execution into an Observation."""

        evidence = [Evidence.model_validate(event) for event in result.events]
        metadata = {
            "execution_success": result.success,
            "execution_error": result.error,
            "duration_ms": result.duration_ms,
            "response_headers": result.headers.copy(),
        }
        if any(
            item.kind == "tool_trace"
            and item.data.get("completeness") == "complete"
            for item in evidence
        ):
            metadata["tool_trace"] = "complete"

        return Observation(
            response_text=result.output_text,
            status_code=result.status_code,
            metadata=metadata,
            evidence=evidence,
        )
