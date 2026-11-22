"""Generic adapter for direct MCP JSON-RPC tool calls over HTTP."""

import json
from datetime import datetime, timezone
from hashlib import sha256
from collections.abc import Mapping
from typing import Any

from core.models import ExecutionResult, TargetProfile, TestInput
from targets.adapters.base import BaseTargetAdapter, TargetAdapterError
from targets.adapters.http_adapter import HttpTargetAdapter
from tools.http import HttpClient, HttpClientError, HttpResponse


class McpJsonRpcTargetAdapter(BaseTargetAdapter):
    """Build MCP ``tools/call`` requests and normalize their responses."""

    def __init__(self, http_client: HttpClient | None = None) -> None:
        self._http_client = http_client or HttpClient()

    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Execute one structured MCP tool call over HTTP POST."""

        config = target.interface.config
        url = HttpTargetAdapter._required_string(config, "url")
        headers = HttpTargetAdapter._headers(
            config.get("headers"), target.credential_refs
        )
        timeout = HttpTargetAdapter._timeout(config.get("timeout"))
        name, arguments = self._tool_call(test_input.parameters)
        live_evidence = config.get("asi05_live_evidence") is True
        if "asi05_live_evidence" in config and type(config["asi05_live_evidence"]) is not bool:
            raise TargetAdapterError("asi05_live_evidence must be a boolean.")
        if live_evidence and "request_id" in config and config["request_id"] != test_input.id:
            raise TargetAdapterError("ASI05 live request_id must equal the execution identity.")
        request_id = self._request_id(test_input.id if live_evidence else config.get("request_id", 1))
        request_event = None
        if live_evidence:
            arguments_hash = sha256(json.dumps(arguments, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            request_event = {
                "kind": "tool_request", "source": "mcp_jsonrpc_adapter",
                "name": name, "reference": "request.params",
                "data": {"provenance": "secagent_request", "execution_verified": False,
                    "request_id": request_id, "arguments_sha256": arguments_hash,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "observation_scope": "secagent_direct_tool_request",
                    "execution_semantics": "direct_tool_request",
                    "verification_status": "request_recorded"},
            }
        request_body = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
            },
        }

        try:
            response = self._http_client.request(
                method="POST",
                url=url,
                headers=headers,
                json_body=request_body,
                timeout=timeout,
            )
        except HttpClientError as exc:
            return ExecutionResult(
                success=False,
                duration_ms=exc.duration_ms,
                error=str(exc),
                events=[request_event] if request_event else [],
            )

        result = self._to_execution_result(response, name, arguments, request_id)
        if request_event:
            result.events = [request_event] + [event for event in result.events
                if not (event.get("kind") == "tool_request" and event.get("source") == "mcp_jsonrpc_adapter")]
        return result

    @staticmethod
    def _tool_call(parameters: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        tool_call = parameters.get("tool_call")
        if not isinstance(tool_call, Mapping):
            raise TargetAdapterError(
                "MCP execution requires a 'parameters.tool_call' mapping."
            )

        name = tool_call.get("name")
        if not isinstance(name, str) or not name.strip():
            raise TargetAdapterError(
                "MCP tool call requires a non-empty string 'name'."
            )

        arguments = tool_call.get("arguments")
        if not isinstance(arguments, Mapping):
            raise TargetAdapterError(
                "MCP tool call requires an 'arguments' mapping."
            )

        return name.strip(), dict(arguments)

    @staticmethod
    def _request_id(value: Any) -> int | str:
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise TargetAdapterError(
                "MCP target 'request_id' must be an integer or string."
            )
        if isinstance(value, str) and not value.strip():
            raise TargetAdapterError(
                "MCP target 'request_id' must not be an empty string."
            )
        return value

    @classmethod
    def _to_execution_result(
        cls,
        response: HttpResponse,
        name: str,
        arguments: dict[str, Any],
        request_id: int | str,
    ) -> ExecutionResult:
        raw_output = (
            response.json_body if response.json_body is not None else response.text
        )
        common = {
            "status_code": response.status_code,
            "raw_output": raw_output,
            "headers": response.headers,
            "duration_ms": response.duration_ms,
        }

        if not 200 <= response.status_code < 300:
            return ExecutionResult(
                success=False,
                output_text=response.text or None,
                error=f"HTTP request returned status code {response.status_code}.",
                **common,
            )

        body = response.json_body
        if not isinstance(body, Mapping):
            return cls._protocol_failure(
                "MCP JSON-RPC response must be a JSON object.", common
            )
        if body.get("jsonrpc") != "2.0":
            return cls._protocol_failure(
                "MCP JSON-RPC response requires jsonrpc='2.0'.", common
            )
        response_id = body.get("id")
        if isinstance(response_id, bool) or response_id != request_id:
            return cls._protocol_failure(
                f"MCP JSON-RPC response id {response_id!r} does not match "
                f"request id {request_id!r}.",
                common,
            )

        if "error" in body:
            error = body["error"]
            message = error.get("message") if isinstance(error, Mapping) else None
            detail = message if isinstance(message, str) and message else "unknown error"
            return cls._protocol_failure(
                f"MCP JSON-RPC error: {detail}", common, response.text or None
            )

        result = body.get("result")
        if not isinstance(result, Mapping):
            return cls._protocol_failure(
                "MCP JSON-RPC response requires a result object.", common
            )
        content = result.get("content")
        if not isinstance(content, list) or not content:
            return cls._protocol_failure(
                "MCP JSON-RPC result requires non-empty content.", common
            )
        first_content = content[0]
        if not isinstance(first_content, Mapping):
            return cls._protocol_failure(
                "MCP JSON-RPC result.content[0] must be an object.", common
            )
        nested_text = first_content.get("text")
        if first_content.get("type") != "text" or not isinstance(nested_text, str):
            return cls._protocol_failure(
                "MCP JSON-RPC result.content[0] must contain text content.", common
            )

        try:
            decoded_result = json.loads(nested_text)
        except json.JSONDecodeError:
            return cls._protocol_failure(
                "MCP JSON-RPC result.content[0].text must contain JSON.",
                common,
                nested_text,
            )
        if not isinstance(decoded_result, Mapping):
            return cls._protocol_failure(
                "MCP JSON-RPC nested tool result must be a JSON object.",
                common,
                nested_text,
            )
        tool_success = decoded_result.get("success")
        if not isinstance(tool_success, bool):
            return cls._protocol_failure(
                "MCP JSON-RPC nested tool result requires boolean 'success'.",
                common,
                nested_text,
            )

        arguments_sha256 = sha256(json.dumps(arguments, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        correlation_reference = "sha256:" + sha256(("mcp-request-id:" + json.dumps(request_id,
            separators=(",", ":"))).encode()).hexdigest()
        events = [
            {
                "kind": "tool_request",
                "source": "mcp_jsonrpc_adapter",
                "name": name,
                "data": {
                    "provenance": "secagent_request",
                    "execution_verified": False,
                    "request_id": request_id,
                    "arguments_sha256": arguments_sha256,
                    "correlation_reference": correlation_reference,
                    "observation_scope": "secagent_direct_tool_request",
                    "execution_semantics": "direct_tool_request",
                    "verification_status": "request_recorded",
                },
                "reference": "request.params",
            },
            {
                "kind": "target_tool_result",
                "source": "mcp_jsonrpc",
                "name": name,
                "data": {
                    "provenance": "target_reported",
                    "execution_verified": False,
                    "reported_success": tool_success,
                    "request_id": request_id,
                    "arguments_sha256": arguments_sha256,
                    "correlation_reference": correlation_reference,
                    "observation_scope": "mcp_target_result",
                    "execution_semantics": "target_reported_result",
                    "verification_status": "target_reported_unverified",
                },
                "reference": "result.content.0.text",
            },
        ]
        return ExecutionResult(
            success=True,
            output_text=nested_text,
            events=events,
            **common,
        )

    @staticmethod
    def _protocol_failure(
        error: str,
        common: dict[str, Any],
        output_text: str | None = None,
    ) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            output_text=output_text,
            error=error,
            **common,
        )
