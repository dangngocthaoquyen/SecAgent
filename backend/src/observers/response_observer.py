"""Normalize an execution result into a response observation."""

from core.models import ExecutionResult, Observation

from observers.base import BaseObserver


class ResponseObserver(BaseObserver):
    """Preserve response data and execution state for later evaluation."""

    def observe(self, result: ExecutionResult) -> Observation:
        """Map a successful or failed execution into an Observation."""

        return Observation(
            response_text=result.output_text,
            status_code=result.status_code,
            metadata={
                "execution_success": result.success,
                "execution_error": result.error,
                "duration_ms": result.duration_ms,
                "response_headers": result.headers.copy(),
            },
        )
