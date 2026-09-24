"""Unit tests for execution-result observation normalization."""

from core.models import ExecutionResult
from observers import ResponseObserver


def test_successful_textual_response_is_normalized() -> None:
    result = ExecutionResult(
        success=True,
        status_code=200,
        output_text="Hello",
        duration_ms=10.5,
    )

    observation = ResponseObserver().observe(result)

    assert observation.response_text == "Hello"
    assert observation.status_code == 200
    assert observation.metadata["execution_success"] is True
    assert observation.metadata["execution_error"] is None
    assert observation.metadata["duration_ms"] == 10.5
    assert "raw_output" not in observation.metadata


def test_network_failure_is_normalized_without_raising() -> None:
    result = ExecutionResult(
        success=False,
        status_code=None,
        output_text=None,
        duration_ms=3.0,
        error="connection refused",
    )

    observation = ResponseObserver().observe(result)

    assert observation.response_text is None
    assert observation.status_code is None
    assert observation.metadata["execution_success"] is False
    assert observation.metadata["execution_error"] == "connection refused"
    assert observation.metadata["duration_ms"] == 3.0


def test_http_failure_preserves_response_and_error_state() -> None:
    result = ExecutionResult(
        success=False,
        status_code=503,
        output_text='{"error":"unavailable"}',
        error="HTTP request returned status code 503.",
    )

    observation = ResponseObserver().observe(result)

    assert observation.status_code == 503
    assert observation.response_text == '{"error":"unavailable"}'
    assert observation.metadata["execution_success"] is False
    assert observation.metadata["execution_error"] == (
        "HTTP request returned status code 503."
    )


def test_success_without_textual_output_is_valid() -> None:
    result = ExecutionResult(
        success=True,
        status_code=204,
        output_text=None,
    )

    observation = ResponseObserver().observe(result)

    assert observation.response_text is None
    assert observation.status_code == 204
    assert observation.metadata["execution_success"] is True


def test_response_headers_are_copied_without_shared_mutable_state() -> None:
    result = ExecutionResult(
        success=True,
        status_code=200,
        headers={"content-type": "application/json"},
    )

    observation = ResponseObserver().observe(result)
    observed_headers = observation.metadata["response_headers"]

    assert observed_headers == {"content-type": "application/json"}

    observed_headers["content-type"] = "text/plain"
    assert result.headers["content-type"] == "application/json"

    result.headers["x-later-change"] = "value"
    assert "x-later-change" not in observed_headers


def test_observe_does_not_mutate_execution_result() -> None:
    result = ExecutionResult(
        success=False,
        status_code=500,
        output_text="failure response",
        raw_output={"error": "details"},
        headers={"content-type": "application/json"},
        duration_ms=7.25,
        error="target failed",
    )
    original_state = result.model_dump()

    ResponseObserver().observe(result)

    assert result.model_dump() == original_state


def test_normalized_events_become_existing_evidence_models() -> None:
    result = ExecutionResult(
        success=True,
        events=[
            {
                "kind": "tool_call",
                "source": "generic_protocol",
                "name": "sensitive_action",
                "success": True,
                "data": {
                    "arguments": {"value": "harmless"},
                    "result": {"success": True},
                },
                "reference": "protocol.result",
            }
        ],
    )

    observation = ResponseObserver().observe(result)

    assert len(observation.evidence) == 1
    assert observation.evidence[0].kind == "tool_call"
    assert observation.evidence[0].name == "sensitive_action"
    assert observation.evidence[0].success is True
    assert observation.evidence[0].data["arguments"] == {"value": "harmless"}


def test_complete_tool_trace_event_propagates_to_observation_metadata() -> None:
    result = ExecutionResult(
        success=True,
        events=[
            {
                "kind": "tool_trace",
                "source": "generic_protocol",
                "data": {"completeness": "complete"},
            }
        ],
    )

    observation = ResponseObserver().observe(result)

    assert observation.metadata["tool_trace"] == "complete"
    assert observation.evidence[0].kind == "tool_trace"


def test_absent_trace_event_does_not_claim_trace_completeness() -> None:
    observation = ResponseObserver().observe(ExecutionResult(success=True))

    assert "tool_trace" not in observation.metadata
