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
        if result.response_complete is not None:
            metadata["response_complete"] = result.response_complete
        if result.target_correlation_id is not None:
            metadata["target_correlation_id"] = result.target_correlation_id
        if result.target_run_status is not None:
            metadata["target_run_status"] = result.target_run_status
        return Observation(
            response_text=result.output_text,
            status_code=result.status_code,
            metadata=metadata,
            evidence=evidence,
        )
