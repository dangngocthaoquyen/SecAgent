"""Unit tests for the generic MCP JSON-RPC target adapter."""

from typing import Any

import pytest

from core.models import TargetInterface, TargetProfile
from core.models import TestInput as CoreTestInput
from targets.adapters import McpJsonRpcTargetAdapter
from tools.http import HttpResponse


class StubHttpClient:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []

    def request(self, **kwargs: Any) -> HttpResponse:
        self.requests.append(kwargs)
        return self.response


def make_target() -> TargetProfile:
    return TargetProfile(
        id="mcp-target",
        name="Generic MCP target",
        target_type="tool_service",
        interface=TargetInterface(
            type="mcp",
            adapter="generic_mcp_jsonrpc",
            config={
                "url": "https://example.invalid/mcp",
                "headers": {"Content-Type": "application/json"},
            },
        ),
    )


def make_input() -> CoreTestInput:
    return CoreTestInput(
        id="input-001",
        parameters={
            "tool_call": {
                "name": "generic_tool",
                "arguments": {"value": "harmless"},
            }
        },
    )


def make_response(
    nested_result: Any,
    *,
    status_code: int = 200,
) -> HttpResponse:
    import json

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(nested_result),
                }
            ]
        },
    }
    return HttpResponse(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=json.dumps(body),
        json_body=body,
        duration_ms=2.5,
    )


def test_valid_tool_call_builds_verified_jsonrpc_request() -> None:
    client = StubHttpClient(
        make_response({"success": True, "output": "completed"})
    )

    result = McpJsonRpcTargetAdapter(client).execute(make_target(), make_input())

    assert client.requests == [
        {
            "method": "POST",
            "url": "https://example.invalid/mcp",
            "headers": {"Content-Type": "application/json"},
            "json_body": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "generic_tool",
                    "arguments": {"value": "harmless"},
                },
            },
            "timeout": None,
        }
    ]
    assert result.success is True
    assert result.raw_output == client.response.json_body
    assert result.output_text == '{"success": true, "output": "completed"}'


def test_successful_tool_result_is_normalized_into_events() -> None:
    client = StubHttpClient(
        make_response({"success": True, "output": "completed"})
    )

    result = McpJsonRpcTargetAdapter(client).execute(make_target(), make_input())

    assert result.events == [
        {
            "kind": "tool_call",
            "source": "mcp_jsonrpc",
            "name": "generic_tool",
            "success": True,
            "data": {
                "arguments": {"value": "harmless"},
                "result": {"success": True, "output": "completed"},
            },
            "reference": "result.content.0.text",
        },
        {
            "kind": "tool_trace",
            "source": "mcp_jsonrpc",
            "data": {"completeness": "complete"},
            "reference": "result.content",
        },
    ]


def test_unsuccessful_tool_result_remains_observable() -> None:
    client = StubHttpClient(
        make_response({"success": False, "error": "denied"})
    )

    result = McpJsonRpcTargetAdapter(client).execute(make_target(), make_input())

    assert result.success is True
    assert result.error is None
    assert result.events[0]["success"] is False
    assert result.events[0]["data"]["result"]["error"] == "denied"
    assert result.events[1]["data"]["completeness"] == "complete"


def test_jsonrpc_error_response_is_an_execution_failure() -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32601, "message": "Method not found"},
    }
    response = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        text='{"jsonrpc":"2.0","id":1,"error":{}}',
        json_body=body,
        duration_ms=1.0,
    )

    result = McpJsonRpcTargetAdapter(StubHttpClient(response)).execute(
        make_target(), make_input()
    )

    assert result.success is False
    assert result.raw_output == body
    assert result.events == []
    assert result.error == "MCP JSON-RPC error: Method not found"


@pytest.mark.parametrize(
    ("content", "error_fragment"),
    [
        ([], "non-empty content"),
        ([{"type": "text", "text": "not-json"}], "must contain JSON"),
        (
            [{"type": "text", "text": '{"output":"missing success"}'}],
            "requires boolean 'success'",
        ),
        ([{"type": "image", "data": "value"}], "text content"),
    ],
)
def test_malformed_nested_content_is_rejected(
    content: list[Any],
    error_fragment: str,
) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": content},
    }
    response = HttpResponse(
        status_code=200,
        headers={},
        text="response",
        json_body=body,
        duration_ms=1.0,
    )

    result = McpJsonRpcTargetAdapter(StubHttpClient(response)).execute(
        make_target(), make_input()
    )

    assert result.success is False
    assert result.events == []
    assert error_fragment in (result.error or "")
