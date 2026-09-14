"""Unit tests for the configuration-driven HTTP target adapter."""

from copy import deepcopy
from typing import Any

import pytest

from core.models import TargetInterface, TargetProfile, TestInput as CoreTestInput
from targets.adapters import HttpTargetAdapter, TargetAdapterError
from tools.http import HttpClientError, HttpResponse


class StubHttpClient:
    def __init__(
        self,
        response: HttpResponse | None = None,
        error: HttpClientError | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.requests: list[dict[str, Any]] = []

    def request(self, **kwargs: Any) -> HttpResponse:
        self.requests.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.response is None:
            raise AssertionError("Stub response was not configured")
        return self.response


def make_response(
    *,
    status_code: int = 200,
    json_body: Any = None,
    text: str = "",
) -> HttpResponse:
    return HttpResponse(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=text,
        json_body=json_body,
        duration_ms=5.0,
    )


def make_target(config: dict[str, Any]) -> TargetProfile:
    return TargetProfile(
        id="target-001",
        name="Example HTTP target",
        target_type="service",
        interface=TargetInterface(
            type="http",
            adapter="generic_http",
            config=config,
        ),
    )


def test_nested_body_template_is_rendered() -> None:
    client = StubHttpClient(
        response=make_response(json_body={"data": {"answer": "Accepted"}})
    )
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "body": {
                "messages": [
                    {"role": "user", "content": "{{input}}"},
                ]
            },
            "response": {"text_path": "data.answer"},
        }
    )

    HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1", prompt="Hello"),
    )

    assert client.requests[0]["json_body"] == {
        "messages": [{"role": "user", "content": "Hello"}]
    }


def test_rendering_does_not_mutate_target_config() -> None:
    client = StubHttpClient(response=make_response(text="Accepted"))
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "body": {"nested": [{"content": "prefix {{input}} suffix"}]},
        }
    )
    original_config = deepcopy(target.interface.config)

    HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1", prompt="Hello"),
    )

    assert target.interface.config == original_config


def test_missing_prompt_for_input_template_raises_clear_error() -> None:
    client = StubHttpClient(response=make_response(text="unused"))
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "body": {"message": "{{input}}"},
        }
    )

    with pytest.raises(TargetAdapterError, match="TestInput.prompt is required"):
        HttpTargetAdapter(client).execute(target, CoreTestInput(id="input-1"))

    assert client.requests == []


def test_nested_list_response_path_extracts_text() -> None:
    client = StubHttpClient(
        response=make_response(
            json_body={
                "choices": [{"message": {"content": "Hello from target"}}]
            }
        )
    )
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "response": {"text_path": "choices.0.message.content"},
        }
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.output_text == "Hello from target"


def test_generic_alternative_response_path_extracts_text() -> None:
    client = StubHttpClient(
        response=make_response(json_body={"data": {"answer": "Generic answer"}})
    )
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "response": {"text_path": "data.answer"},
        }
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.output_text == "Generic answer"


def test_missing_response_path_returns_clear_failed_result() -> None:
    client = StubHttpClient(
        response=make_response(json_body={"data": {"other": "value"}})
    )
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "response": {"text_path": "data.answer"},
        }
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.success is False
    assert result.status_code == 200
    assert result.error is not None
    assert "Response text path not found" in result.error


def test_http_200_returns_successful_execution_result() -> None:
    client = StubHttpClient(response=make_response(text="plain response"))
    target = make_target(
        {"url": "https://example.invalid/execute", "method": "GET"}
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.success is True
    assert result.status_code == 200
    assert result.output_text == "plain response"


def test_non_2xx_returns_failed_execution_result_with_body() -> None:
    client = StubHttpClient(
        response=make_response(
            status_code=503,
            json_body={"error": "unavailable"},
            text='{"error":"unavailable"}',
        )
    )
    target = make_target(
        {"url": "https://example.invalid/execute", "method": "POST"}
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.success is False
    assert result.status_code == 503
    assert result.raw_output == {"error": "unavailable"}
    assert result.error == "HTTP request returned status code 503."


def test_network_error_returns_failed_execution_result_without_status() -> None:
    client = StubHttpClient(
        error=HttpClientError("HTTP request failed: connection refused", duration_ms=3.0)
    )
    target = make_target(
        {"url": "https://example.invalid/execute", "method": "POST"}
    )

    result = HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert result.success is False
    assert result.status_code is None
    assert result.duration_ms == 3.0
    assert result.error == "HTTP request failed: connection refused"


def test_headers_and_timeout_are_forwarded_from_target_config() -> None:
    client = StubHttpClient(response=make_response(text="Accepted"))
    target = make_target(
        {
            "url": "https://example.invalid/execute",
            "method": "POST",
            "headers": {"X-Test": "abc"},
            "timeout": 5,
        }
    )

    HttpTargetAdapter(client).execute(
        target,
        CoreTestInput(id="input-1"),
    )

    assert client.requests[0]["headers"] == {"X-Test": "abc"}
    assert client.requests[0]["timeout"] == 5.0
