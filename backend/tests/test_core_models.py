"""Unit tests for the Day 1 core domain models."""

import pytest
from pydantic import ValidationError

from core.models import (
    ExecutionResult,
    Observation,
    TargetInterface,
    TargetProfile,
    TestInput as CoreTestInput,
)


def test_target_profile_can_be_created_and_serialized() -> None:
    profile = TargetProfile(
        id="target-001",
        name="Example agent",
        target_type="ai_agent",
        interface=TargetInterface(
            type="http",
            adapter="generic_http",
            config={
                "url": "https://example.invalid",
                "method": "POST",
            },
        ),
        capabilities=["chat"],
        observability=["response", "tool_calls", "traces"],
    )

    dumped = profile.model_dump()

    assert dumped["id"] == "target-001"
    assert dumped["interface"]["type"] == "http"
    assert dumped["observability"] == ["response", "tool_calls", "traces"]
    assert dumped["metadata"] == {}


def test_test_input_can_be_created_and_serialized() -> None:
    test_input = CoreTestInput(
        id="test-001",
        prompt="Summarize this input.",
        parameters={"temperature": 0},
    )

    dumped = test_input.model_dump()

    assert dumped["prompt"] == "Summarize this input."
    assert dumped["artifact_refs"] == []
    assert dumped["parameters"] == {"temperature": 0}


def test_invalid_target_interface_config_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        TargetInterface(
            type="http",
            adapter="generic_http",
            config=["not", "a", "mapping"],
        )


def test_config_facing_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        TargetInterface(
            type="http",
            adapter="generic_http",
            config={},
            adaptr="typo",
        )

    with pytest.raises(ValidationError):
        TargetProfile(
            id="target-typo",
            name="Typo target",
            target_type="ai_agent",
            interface=TargetInterface(
                type="http",
                adapter="generic_http",
                config={},
            ),
            observabilty=["response"],
        )


def test_test_input_without_prompt_is_valid() -> None:
    test_input = CoreTestInput(
        id="test-002",
        file_refs=["file://sample.bin"],
        environment={"mode": "file_scan"},
    )

    assert test_input.prompt is None
    assert test_input.file_refs == ["file://sample.bin"]


def test_execution_result_is_valid() -> None:
    result = ExecutionResult(
        success=True,
        status_code=202,
        raw_output={"job_id": "job-001"},
        events=[{"type": "accepted"}],
        duration_ms=12.5,
    )

    assert result.output_text is None
    assert result.duration_ms == 12.5
    assert result.model_dump()["raw_output"] == {"job_id": "job-001"}


def test_negative_execution_duration_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        ExecutionResult(success=False, duration_ms=-0.1)


def test_observation_is_valid_without_textual_response() -> None:
    observation = Observation(
        tool_calls=[{"name": "scan_file", "arguments": {"file": "sample.bin"}}],
        evidence_refs=["artifact://scan-result-001"],
    )

    assert observation.response_text is None
    assert observation.tool_calls[0]["name"] == "scan_file"
    assert observation.model_dump()["evidence_refs"] == ["artifact://scan-result-001"]


def test_mutable_defaults_are_not_shared_between_instances() -> None:
    first = CoreTestInput(id="test-003")
    second = CoreTestInput(id="test-004")

    first.file_refs.append("file://first.bin")
    first.metadata["source"] = "first"

    assert second.file_refs == []
    assert second.metadata == {}
