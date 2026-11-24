"""Reusable, configuration-driven MCP Agent Runtime core (Stage 3B).

Executes an LLM-driven tool-selection loop (`subject='agent_run'`,
`attribution='agent_selected'`) against a reviewed LLM endpoint, reviewed static
tool catalog, and stateless HTTP JSON-RPC 2.0 MCP client within strict bounds.
This core is decoupled from Flask, Workflow orchestrators, ExecutionGrant
storage, Judge evaluators, Reporting, and Bridge :7019.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
import re
from time import monotonic
from typing import Any, Callable, Literal, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
TOOL_CALL_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
HEX64_RE = re.compile(r"^[a-f0-9]{64}$")

SUPPORTED_SCHEMA_KEYS = frozenset({
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "items",
    "minItems",
    "maxItems",
    "title",
    "description",
    "default",
})
UNSUPPORTED_SCHEMA_KEYS = frozenset({
    "$ref",
    "$defs",
    "definitions",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
    "patternProperties",
    "dependentSchemas",
    "dependentRequired",
    "const",
})
SUPPORTED_TYPES = frozenset({"string", "integer", "number", "boolean", "array", "object", "null"})
MAX_SCHEMA_DEPTH = 4
DEFAULT_MCP_PATHS = frozenset({"/", "/mcp", "/jsonrpc"})


def compute_text_sha256(text: str) -> str:
    """Compute canonical UTF-8 SHA-256 digest for reviewed prompt text."""
    return sha256(text.encode("utf-8")).hexdigest()


def compute_tool_catalog_sha256(tools: tuple["ReviewedToolSpec", ...] | list["ReviewedToolSpec"]) -> str:
    """Compute canonical SHA-256 digest for a reviewed static tool catalog."""
    payload = [tool.model_dump(mode="json") for tool in tools]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


def _validate_endpoint_url(value: str, *, require_mcp_path: bool = False) -> str:
    if (not isinstance(value, str) or not value or len(value) > 512
            or value != value.strip() or "\\" in value
            or any(c.isspace() or ord(c) < 32 for c in value)):
        raise ValueError("Endpoint URL must be clean without whitespace or control characters.")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.port == 0):
        raise ValueError("Endpoint URL must be an HTTP(S) URL without credentials, query, or fragment.")
    if require_mcp_path and (parsed.path or "/") not in DEFAULT_MCP_PATHS:
        raise ValueError("MCP endpoint path must be '/', '/mcp', or '/jsonrpc'.")
    return value


def _validate_restricted_schema(schema: Any, *, depth: int = 0, top_level: bool = False) -> None:
    """Validate that a tool schema uses only our documented fail-closed JSON Schema subset.

    Unsupported constructs (e.g. $ref, anyOf, oneOf, allOf, not, patternProperties)
    are rejected explicitly rather than ignored.
    """
    if depth > MAX_SCHEMA_DEPTH:
        raise ValueError("Tool inputSchema exceeds maximum nesting depth.")
    if not isinstance(schema, dict):
        raise ValueError("Tool inputSchema must be a mapping.")
    unknown = set(schema) - SUPPORTED_SCHEMA_KEYS
    if unknown:
        bad = sorted(unknown)
        unsupported = sorted(unknown & UNSUPPORTED_SCHEMA_KEYS)
        detail = unsupported if unsupported else bad
        raise ValueError(f"Unsupported JSON Schema construct: {detail[0]}")
    schema_type = schema.get("type")
    if schema_type not in SUPPORTED_TYPES:
        raise ValueError("Tool schema requires a supported string 'type'.")
    if top_level and schema_type != "object":
        raise ValueError("Top-level tool inputSchema must have type='object'.")
    if "enum" in schema:
        enum_values = schema["enum"]
        if not isinstance(enum_values, list) or not enum_values or len(enum_values) > 64:
            raise ValueError("Schema 'enum' must be a bounded non-empty list.")
    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str) or len(pattern) > 256:
            raise ValueError("Schema 'pattern' must be a bounded string.")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError("Schema 'pattern' is invalid regex.") from exc
    for int_bound in ("minLength", "maxLength", "minItems", "maxItems"):
        if int_bound in schema and (type(schema[int_bound]) is not int or schema[int_bound] < 0):
            raise ValueError(f"Schema {int_bound!r} must be a non-negative integer.")
    for num_bound in ("minimum", "maximum"):
        if num_bound in schema:
            val = schema[num_bound]
            if type(val) not in (int, float) or not math.isfinite(val):
                raise ValueError(f"Schema {num_bound!r} must be a finite number.")
    if schema_type == "object":
        props = schema.get("properties", {})
        if not isinstance(props, dict) or len(props) > 64:
            raise ValueError("Object schema 'properties' must be a bounded mapping.")
        for key, prop_schema in props.items():
            if not isinstance(key, str) or not key:
                raise ValueError("Object schema property names must be non-empty strings.")
            _validate_restricted_schema(prop_schema, depth=depth + 1, top_level=False)
        req = schema.get("required", [])
        if not isinstance(req, list) or any(not isinstance(item, str) for item in req):
            raise ValueError("Object schema 'required' must be a list of strings.")
        if any(item not in props for item in req):
            raise ValueError("Object schema 'required' references undeclared property.")
        if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
            raise ValueError("Schema 'additionalProperties' must be a boolean.")
    elif schema_type == "array" and "items" in schema:
        _validate_restricted_schema(schema["items"], depth=depth + 1, top_level=False)


def validate_restricted_tool_schema(schema: Any) -> tuple[bool, str | None]:
    """Validate a discovered MCP inputSchema against SecAgent's restricted schema subset.

    Returns ``(True, None)`` when compatible, or ``(False, fixed_error_code)`` without
    guessing unsupported constructs or echoing arbitrary untrusted text.
    """
    if schema is None:
        return False, "missing_input_schema"
    if not isinstance(schema, dict):
        return False, "invalid_input_schema"
    try:
        _validate_restricted_schema(schema, depth=0, top_level=True)
    except ValueError as exc:
        detail = str(exc)
        if "Unsupported JSON Schema construct" in detail:
            return False, "unsupported_schema_keyword"
        if "maximum nesting depth" in detail:
            return False, "schema_nesting_too_deep"
        if "type='object'" in detail or "supported string 'type'" in detail:
            return False, "unsupported_root_schema_type"
        return False, "invalid_input_schema"
    return True, None


def _validate_value_against_schema(value: Any, schema: dict[str, Any], *, path: str = "$") -> str | None:
    """Validate parsed JSON arguments against the reviewed restricted schema subset."""
    expected = schema["type"]
    if expected == "string":
        if type(value) is not str:
            return f"argument_type_mismatch:{path}"
        if "minLength" in schema and len(value) < schema["minLength"]:
            return f"argument_min_length:{path}"
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return f"argument_max_length:{path}"
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return f"argument_pattern_mismatch:{path}"
    elif expected == "integer":
        if type(value) is not int:
            return f"argument_type_mismatch:{path}"
        if "minimum" in schema and value < schema["minimum"]:
            return f"argument_minimum:{path}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"argument_maximum:{path}"
    elif expected == "number":
        if type(value) not in (int, float) or not math.isfinite(value):
            return f"argument_type_mismatch:{path}"
        if "minimum" in schema and value < schema["minimum"]:
            return f"argument_minimum:{path}"
        if "maximum" in schema and value > schema["maximum"]:
            return f"argument_maximum:{path}"
    elif expected == "boolean":
        if type(value) is not bool:
            return f"argument_type_mismatch:{path}"
    elif expected == "null":
        if value is not None:
            return f"argument_type_mismatch:{path}"
    elif expected == "array":
        if type(value) is not list:
            return f"argument_type_mismatch:{path}"
        if "minItems" in schema and len(value) < schema["minItems"]:
            return f"argument_min_items:{path}"
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return f"argument_max_items:{path}"
        item_schema = schema.get("items")
        if item_schema is not None:
            for idx, item in enumerate(value):
                err = _validate_value_against_schema(item, item_schema, path=f"{path}[{idx}]")
                if err is not None:
                    return err
    elif expected == "object":
        if type(value) is not dict:
            return f"argument_type_mismatch:{path}"
        props = schema.get("properties", {})
        for req_key in schema.get("required", ()):
            if req_key not in value:
                return f"argument_missing_required:{path}.{req_key}"
        allow_extra = schema.get("additionalProperties", False)
        for key, item in value.items():
            if not isinstance(key, str):
                return f"argument_invalid_key:{path}"
            if key in props:
                err = _validate_value_against_schema(item, props[key], path=f"{path}.{key}")
                if err is not None:
                    return err
            elif not allow_extra:
                return f"argument_unexpected_property:{path}.{key}"
    if "enum" in schema:
        if not any(type(value) is type(candidate) and value == candidate for candidate in schema["enum"]):
            return f"argument_enum_mismatch:{path}"
    return None


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReviewedToolSpec(_ClosedModel):
    """Immutable server-reviewed MCP tool definition and restricted schema."""

    name: str
    description: str = Field(min_length=1, max_length=1024)
    input_schema: dict[str, Any]

    @model_validator(mode="after")
    def validate_tool(self):
        if not TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError("Invalid MCP tool name.")
        _validate_restricted_schema(self.input_schema, depth=0, top_level=True)
        return self

    def openai_tool_definition(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": deepcopy(self.input_schema),
            },
        }


class EnvironmentAuthorizationScope(_ClosedModel):
    """Operator-authorized disposable lab resource limits separate from tool exposure and evaluation."""

    allowed_write_path_prefixes: list[str] | None = Field(default=None, max_length=16)
    write_scoped_tools: list[str] = Field(default_factory=lambda: ["write_file"], max_length=8)
    allowed_fetch_hosts: list[str] | None = Field(default=None, max_length=32)
    fetch_scoped_tools: list[str] = Field(default_factory=lambda: ["fetch_url"], max_length=8)

    @model_validator(mode="after")
    def validate_scope(self):
        if self.allowed_write_path_prefixes is not None:
            for prefix in self.allowed_write_path_prefixes:
                if (
                    not isinstance(prefix, str)
                    or not prefix
                    or "\x00" in prefix
                    or ".." in prefix.replace("\\", "/").split("/")
                ):
                    raise ValueError("Invalid allowed write path prefix.")
        if self.allowed_fetch_hosts is not None:
            for host in self.allowed_fetch_hosts:
                if not isinstance(host, str) or not host or any(c.isspace() for c in host):
                    raise ValueError("Invalid allowed fetch host.")
        return self


class McpAgentRuntimeConfig(_ClosedModel):
    """Immutable reviewed runtime configuration binding LLM and MCP identities."""

    llm_target_id: str
    llm_profile_revision: str
    llm_endpoint: str
    model: str
    credential_env: str | None = None
    system_prompt: str = Field(min_length=1, max_length=32768)
    system_prompt_sha256: str

    mcp_target_id: str
    mcp_profile_revision: str
    mcp_endpoint: str
    mcp_credential_env: str | None = None
    reviewed_tools: tuple[ReviewedToolSpec, ...] = Field(min_length=1, max_length=64)
    tool_catalog_sha256: str
    target_composition: Literal["hosted_mcp_agent"] = "hosted_mcp_agent"
    environment_scope: EnvironmentAuthorizationScope | None = None

    max_model_calls: int = Field(default=4, ge=1, le=4)
    max_tool_calls: int = Field(default=3, ge=0, le=3)
    max_nested_requests: Literal[0] = 0
    llm_timeout_seconds: float = Field(default=15.0, gt=0.0, le=60.0)
    mcp_timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    total_timeout_seconds: float = Field(default=45.0, gt=0.0, le=120.0)
    max_response_bytes: int = Field(default=131072, ge=1024, le=1048576)

    @model_validator(mode="after")
    def validate_bindings(self):
        for field_val, label in ((self.llm_target_id, "llm_target_id"), (self.mcp_target_id, "mcp_target_id")):
            if not IDENTIFIER_RE.fullmatch(field_val):
                raise ValueError(f"Invalid {label}.")
        for digest_val, label in (
            (self.llm_profile_revision, "llm_profile_revision"),
            (self.system_prompt_sha256, "system_prompt_sha256"),
            (self.mcp_profile_revision, "mcp_profile_revision"),
            (self.tool_catalog_sha256, "tool_catalog_sha256"),
        ):
            if not HEX64_RE.fullmatch(digest_val):
                raise ValueError(f"Invalid SHA-256 digest for {label}.")
        if not MODEL_NAME_RE.fullmatch(self.model):
            raise ValueError("Invalid LLM model identifier.")
        for env_name, label in ((self.credential_env, "credential_env"), (self.mcp_credential_env, "mcp_credential_env")):
            if env_name is not None and not ENV_NAME_RE.fullmatch(env_name):
                raise ValueError(f"Invalid environment variable name for {label}.")
        if self.credential_env is not None and self.mcp_credential_env == self.credential_env:
            raise ValueError("LLM and MCP credentials must remain isolated.")
        _validate_endpoint_url(self.llm_endpoint, require_mcp_path=False)
        _validate_endpoint_url(self.mcp_endpoint, require_mcp_path=True)
        if compute_text_sha256(self.system_prompt) != self.system_prompt_sha256:
            raise ValueError("system_prompt does not match system_prompt_sha256.")
        names = [tool.name for tool in self.reviewed_tools]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate tool names in reviewed_tools.")
        if compute_tool_catalog_sha256(self.reviewed_tools) != self.tool_catalog_sha256:
            raise ValueError("reviewed_tools does not match tool_catalog_sha256.")
        return self

    def config_digest(self) -> str:
        encoded = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return sha256(encoded.encode("utf-8")).hexdigest()


class GuardCheckContext(_ClosedModel):
    """Information passed to the mandatory ExecutionGuard before every external step."""

    run_id: str
    step_kind: Literal["llm_completion", "mcp_tool_call"]
    model_calls_used: int
    tool_calls_used: int
    config_digest: str
    target_endpoint: str
    tool_name: str | None = None
    tool_scope_claims: tuple[tuple[str, str], ...] | None = None


class GuardDecision(_ClosedModel):
    allowed: bool
    reason: str | None = None
    cancelled: bool = False


class ExecutionGuard(Protocol):
    def check(self, context: GuardCheckContext) -> GuardDecision:
        """Return whether the outbound LLM or MCP step is currently authorized."""


class LlmToolCall(_ClosedModel):
    id: Any
    name: Any
    arguments: Any


class LlmChatRequest(_ClosedModel):
    endpoint: str
    model: str
    messages: tuple[dict[str, Any], ...]
    tools: tuple[dict[str, Any], ...]
    credential_env: str | None
    timeout_seconds: float
    max_response_bytes: int


class LlmChatResponse(_ClosedModel):
    role: Any
    content: Any
    finish_reason: Any
    tool_calls: tuple[LlmToolCall, ...] | None = None


class LlmChatClient(Protocol):
    def complete(self, request: LlmChatRequest) -> LlmChatResponse:
        """Send one bounded OpenAI-compatible chat completion request."""


class McpToolRequest(_ClosedModel):
    endpoint: str
    tool_name: str
    arguments: dict[str, Any]
    request_id: str
    credential_env: str | None
    timeout_seconds: float
    max_response_bytes: int


class McpToolResponse(_ClosedModel):
    success: bool
    content_text: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    target_reported_success: bool | None = None


class McpToolClient(Protocol):
    def call_tool(self, request: McpToolRequest) -> McpToolResponse:
        """Send one stateless JSON-RPC 2.0 tools/call HTTP POST request."""


class AgentRuntimeTraceEvent(_ClosedModel):
    """Typed internal execution trace event; never auto-verified."""

    kind: Literal["agent_tool_intent", "secagent_mcp_request", "target_mcp_response", "rejected_tool_call"]
    provenance: Literal["model_reported", "secagent_request", "target_reported", "secagent_policy"]
    execution_verified: Literal[False] = False
    subject: Literal["agent_run"] = "agent_run"
    attribution: Literal["agent_selected"] = "agent_selected"
    run_id: str
    sequence_index: int
    model_call_index: int
    tool_call_id: str | None = None
    invocation_id: str | None = None
    tool_name: str | None = None
    arguments_sha256: str | None = None
    request_status: str | None = None
    response_status: str | None = None
    target_reported_success: bool | None = None
    result_sha256: str | None = None
    reason: str | None = None
    timestamp: str


class AgentRuntimeResult(_ClosedModel):
    """Normalized outcome from one McpAgentRuntime execution."""

    run_id: str
    subject: Literal["agent_run"] = "agent_run"
    attribution: Literal["agent_selected"] = "agent_selected"
    target_composition: Literal["hosted_mcp_agent"] = "hosted_mcp_agent"
    status: Literal["completed", "incomplete", "blocked", "budget_exhausted", "timeout", "cancelled", "error"]
    completion_status: str
    assistant_text: str | None = None
    response_complete: bool = False
    model_call_count: int = 0
    tool_call_count: int = 0
    rejected_tool_call_count: int = 0
    events: tuple[AgentRuntimeTraceEvent, ...] = ()
    error: str | None = None
    llm_target_id: str
    llm_profile_revision: str
    model: str
    system_prompt_sha256: str
    mcp_target_id: str
    mcp_profile_revision: str
    tool_catalog_sha256: str


class RuntimeTransportError(Exception):
    """Safe bounded transport error without raw URLs or secrets."""


def _read_bounded_json(
    client: httpx.Client,
    *,
    url: str,
    headers: dict[str, str],
    json_body: dict[str, Any],
    timeout: float,
    max_bytes: int,
) -> tuple[int, Any]:
    with client.stream("POST", url, headers=headers, json=json_body, timeout=timeout) as response:
        if 300 <= response.status_code < 400 or response.is_redirect:
            raise RuntimeTransportError("redirect_rejected")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeTransportError("response_too_large")
            chunks.append(chunk)
        raw = b"".join(chunks)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    return response.status_code, parsed


class HttpLlmChatClient:
    """Bounded OpenAI-compatible HTTP chat client resolving credential_env only at header time."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def complete(self, request: LlmChatRequest) -> LlmChatResponse:
        _validate_endpoint_url(request.endpoint, require_mcp_path=False)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if request.credential_env is not None:
            secret = os.environ.get(request.credential_env)
            if not secret or not secret.strip():
                raise RuntimeTransportError("llm_credential_missing")
            headers["Authorization"] = f"Bearer {secret}"
        body = {
            "model": request.model,
            "messages": list(request.messages),
            "tools": list(request.tools),
            "tool_choice": "auto",
            "stream": False,
        }
        try:
            with httpx.Client(transport=self._transport, follow_redirects=False, trust_env=False) as client:
                status_code, payload = _read_bounded_json(
                    client,
                    url=request.endpoint,
                    headers=headers,
                    json_body=body,
                    timeout=request.timeout_seconds,
                    max_bytes=request.max_response_bytes,
                )
        except httpx.TimeoutException:
            raise RuntimeTransportError("llm_timeout") from None
        except httpx.RequestError:
            raise RuntimeTransportError("llm_transport_error") from None
        if not 200 <= status_code < 300:
            raise RuntimeTransportError(f"llm_http_status_{status_code}")
        if not isinstance(payload, dict):
            raise RuntimeTransportError("llm_malformed_response")
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise RuntimeTransportError("llm_malformed_response")
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            raise RuntimeTransportError("llm_malformed_response")
        raw_calls = message.get("tool_calls")
        parsed_calls: tuple[LlmToolCall, ...] | None = None
        if raw_calls is not None:
            if not isinstance(raw_calls, list):
                raise RuntimeTransportError("llm_malformed_tool_calls")
            items: list[LlmToolCall] = []
            for entry in raw_calls:
                if not isinstance(entry, dict) or entry.get("type") not in (None, "function"):
                    raise RuntimeTransportError("llm_malformed_tool_calls")
                fn = entry.get("function")
                if not isinstance(fn, dict):
                    raise RuntimeTransportError("llm_malformed_tool_calls")
                items.append(LlmToolCall(
                    id=entry.get("id"),
                    name=fn.get("name"),
                    arguments=fn.get("arguments"),
                ))
            parsed_calls = tuple(items)
        return LlmChatResponse(
            role=message.get("role"),
            content=message.get("content"),
            finish_reason=choice.get("finish_reason"),
            tool_calls=parsed_calls,
        )


class HttpMcpToolClient:
    """Stateless HTTP POST JSON-RPC 2.0 MCP tools/call client isolated from LLM credentials."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def call_tool(self, request: McpToolRequest) -> McpToolResponse:
        _validate_endpoint_url(request.endpoint, require_mcp_path=True)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if request.credential_env is not None:
            secret = os.environ.get(request.credential_env)
            if not secret or not secret.strip():
                return McpToolResponse(success=False, error_code="mcp_credential_missing", error_message="mcp_credential_missing")
            headers["Authorization"] = f"Bearer {secret}"
        rpc_body = {
            "jsonrpc": "2.0",
            "id": request.request_id,
            "method": "tools/call",
            "params": {
                "name": request.tool_name,
                "arguments": request.arguments,
            },
        }
        try:
            with httpx.Client(transport=self._transport, follow_redirects=False, trust_env=False) as client:
                status_code, payload = _read_bounded_json(
                    client,
                    url=request.endpoint,
                    headers=headers,
                    json_body=rpc_body,
                    timeout=request.timeout_seconds,
                    max_bytes=request.max_response_bytes,
                )
        except RuntimeTransportError as exc:
            return McpToolResponse(success=False, error_code=str(exc), error_message=str(exc))
        except httpx.TimeoutException:
            return McpToolResponse(success=False, error_code="mcp_timeout", error_message="mcp_timeout")
        except httpx.RequestError:
            return McpToolResponse(success=False, error_code="mcp_transport_error", error_message="mcp_transport_error")

        if not 200 <= status_code < 300:
            return McpToolResponse(success=False, error_code=f"mcp_http_status_{status_code}", error_message=f"mcp_http_status_{status_code}")
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
            return McpToolResponse(success=False, error_code="mcp_malformed_jsonrpc", error_message="mcp_malformed_jsonrpc")
        resp_id = payload.get("id")
        if isinstance(resp_id, bool) or resp_id != request.request_id:
            return McpToolResponse(success=False, error_code="mcp_response_id_mismatch", error_message="mcp_response_id_mismatch")
        if "error" in payload:
            err = payload["error"]
            code = "mcp_jsonrpc_error"
            if isinstance(err, dict) and isinstance(err.get("code"), int):
                code = f"mcp_jsonrpc_error_{err['code']}"
            return McpToolResponse(success=False, error_code=code, error_message="mcp_jsonrpc_error", target_reported_success=False)
        result = payload.get("result")
        if not isinstance(result, dict):
            return McpToolResponse(success=False, error_code="mcp_malformed_result", error_message="mcp_malformed_result")
        target_reported_success: bool | None = None
        content = result.get("content")
        if isinstance(content, list):
            texts = [
                item.get("text")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str)
            ]
            content_text = "\n".join(texts) if texts else json.dumps(result, sort_keys=True, ensure_ascii=False)
            if texts:
                try:
                    decoded = json.loads(texts[0])
                    if isinstance(decoded, dict) and type(decoded.get("success")) is bool:
                        target_reported_success = decoded["success"]
                except ValueError:
                    pass
        else:
            content_text = json.dumps(result, sort_keys=True, ensure_ascii=False)
        return McpToolResponse(success=True, content_text=content_text, target_reported_success=target_reported_success)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_id_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and TOOL_CALL_ID_RE.fullmatch(value) else None


def _safe_name_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and TOOL_NAME_RE.fullmatch(value) else None


def _reject_nonfinite_json(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant not allowed: {token}")


def _strict_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError(f"Duplicate JSON object key: {key}")
        obj[key] = val
    return obj


def _parse_strict_json_arguments(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(raw, str):
        return None, "invalid_argument_json"
    try:
        parsed = json.loads(
            raw,
            parse_constant=_reject_nonfinite_json,
            object_pairs_hook=_strict_json_object_pairs,
        )
    except ValueError:
        return None, "invalid_argument_json"
    if type(parsed) is not dict:
        return None, "argument_type_mismatch:$"
    return parsed, None


def _hash_raw_arguments(raw_args: Any) -> str:
    if isinstance(raw_args, str):
        return sha256(raw_args.encode("utf-8", errors="replace")).hexdigest()
    return sha256(repr(raw_args).encode("utf-8", errors="replace")).hexdigest()


class McpAgentRuntime:
    """Reusable bounded runtime for autonomous LLM tool selection over reviewed MCP catalogs."""

    def __init__(
        self,
        *,
        llm_client: LlmChatClient,
        mcp_client: McpToolClient,
        execution_guard: ExecutionGuard,
        cancellation_requested: Callable[[], bool] | None = None,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if llm_client is None or mcp_client is None or execution_guard is None:
            raise ValueError("llm_client, mcp_client, and explicit execution_guard are required.")
        self._llm_client = llm_client
        self._mcp_client = mcp_client
        self._guard = execution_guard
        self._cancellation_requested = cancellation_requested
        self._clock = clock
        self.last_dispatched_tool_arguments: dict[str, tuple[str, str, dict[str, Any]]] = {}

    def run(self, prompt: str, config: McpAgentRuntimeConfig) -> AgentRuntimeResult:
        self.last_dispatched_tool_arguments = {}
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Testcase prompt must be a non-empty string.")
        if not isinstance(config, McpAgentRuntimeConfig):
            raise ValueError("A validated McpAgentRuntimeConfig is required.")

        run_id = uuid4().hex
        config_snapshot = config.model_copy(deep=True)
        expected_digest = config_snapshot.config_digest()
        tool_map = {tool.name: tool for tool in config_snapshot.reviewed_tools}
        tool_schemas = tuple(tool.openai_tool_definition() for tool in config_snapshot.reviewed_tools)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": config_snapshot.system_prompt},
            {"role": "user", "content": prompt},
        ]

        deadline = self._clock() + config_snapshot.total_timeout_seconds
        events: list[AgentRuntimeTraceEvent] = []
        model_calls_used = 0
        tool_calls_used = 0
        rejected_count = 0
        seen_tool_call_ids: set[str] = set()
        dispatched_invocations: set[str] = set()

        def emit(
            *,
            kind: Literal["agent_tool_intent", "secagent_mcp_request", "target_mcp_response", "rejected_tool_call"],
            provenance: Literal["model_reported", "secagent_request", "target_reported", "secagent_policy"],
            model_idx: int,
            tool_call_id: str | None = None,
            invocation_id: str | None = None,
            tool_name: str | None = None,
            arguments_sha256: str | None = None,
            request_status: str | None = None,
            response_status: str | None = None,
            target_reported_success: bool | None = None,
            result_sha256: str | None = None,
            reason: str | None = None,
        ) -> None:
            events.append(AgentRuntimeTraceEvent(
                kind=kind,
                provenance=provenance,
                run_id=run_id,
                sequence_index=len(events),
                model_call_index=model_idx,
                tool_call_id=tool_call_id,
                invocation_id=invocation_id,
                tool_name=tool_name,
                arguments_sha256=arguments_sha256,
                request_status=request_status,
                response_status=response_status,
                target_reported_success=target_reported_success,
                result_sha256=result_sha256,
                reason=reason,
                timestamp=_now_iso(),
            ))

        def build_result(
            *,
            status: Literal["completed", "incomplete", "blocked", "budget_exhausted", "timeout", "cancelled", "error"],
            completion_status: str,
            assistant_text: str | None = None,
            response_complete: bool = False,
            error: str | None = None,
        ) -> AgentRuntimeResult:
            safe_text = self._redact_secrets(assistant_text, config_snapshot) if isinstance(assistant_text, str) else None
            safe_err = self._redact_secrets(error, config_snapshot) if isinstance(error, str) else None
            return AgentRuntimeResult(
                run_id=run_id,
                target_composition=config_snapshot.target_composition,
                status=status,
                completion_status=completion_status,
                assistant_text=safe_text,
                response_complete=response_complete,
                model_call_count=model_calls_used,
                tool_call_count=tool_calls_used,
                rejected_tool_call_count=rejected_count,
                events=tuple(events),
                error=safe_err,
                llm_target_id=config_snapshot.llm_target_id,
                llm_profile_revision=config_snapshot.llm_profile_revision,
                model=config_snapshot.model,
                system_prompt_sha256=config_snapshot.system_prompt_sha256,
                mcp_target_id=config_snapshot.mcp_target_id,
                mcp_profile_revision=config_snapshot.mcp_profile_revision,
                tool_catalog_sha256=config_snapshot.tool_catalog_sha256,
            )

        def preflight(
            step_kind: Literal["llm_completion", "mcp_tool_call"],
            tool_name: str | None = None,
            tool_scope_claims: tuple[tuple[str, str], ...] | None = None,
        ) -> tuple[str, str] | None:
            if (config.config_digest() != expected_digest
                    or compute_text_sha256(config_snapshot.system_prompt) != config_snapshot.system_prompt_sha256
                    or compute_tool_catalog_sha256(config_snapshot.reviewed_tools) != config_snapshot.tool_catalog_sha256):
                return "blocked", "config_integrity_changed"
            if self._cancellation_requested is not None and self._cancellation_requested():
                return "cancelled", "operator_cancelled"
            if self._clock() >= deadline:
                return "timeout", "total_deadline_exceeded"
            if step_kind == "llm_completion" and model_calls_used >= config_snapshot.max_model_calls:
                return "budget_exhausted", "model_call_budget_exhausted"
            if step_kind == "mcp_tool_call" and tool_calls_used >= config_snapshot.max_tool_calls:
                return "budget_exhausted", "tool_call_budget_exhausted"
            target_ep = config_snapshot.llm_endpoint if step_kind == "llm_completion" else config_snapshot.mcp_endpoint
            decision = self._guard.check(GuardCheckContext(
                run_id=run_id,
                step_kind=step_kind,
                model_calls_used=model_calls_used,
                tool_calls_used=tool_calls_used,
                config_digest=expected_digest,
                target_endpoint=target_ep,
                tool_name=tool_name,
                tool_scope_claims=tool_scope_claims,
            ))
            if not isinstance(decision, GuardDecision):
                return "blocked", "guard_invalid_decision"
            if decision.cancelled:
                return "cancelled", decision.reason or "operator_cancelled"
            if not decision.allowed:
                return "blocked", decision.reason or "execution_guard_rejected"
            return None

        while True:
            blocked = preflight("llm_completion")
            if blocked is not None:
                status, reason = blocked
                return build_result(status=status, completion_status=reason, error=reason)

            remaining = max(0.001, deadline - self._clock())
            llm_timeout = min(config_snapshot.llm_timeout_seconds, remaining)
            llm_request = LlmChatRequest(
                endpoint=config_snapshot.llm_endpoint,
                model=config_snapshot.model,
                messages=tuple(deepcopy(messages)),
                tools=tool_schemas,
                credential_env=config_snapshot.credential_env,
                timeout_seconds=llm_timeout,
                max_response_bytes=config_snapshot.max_response_bytes,
            )
            model_calls_used += 1
            model_idx = model_calls_used
            try:
                llm_response = self._llm_client.complete(llm_request)
            except RuntimeTransportError as exc:
                code = str(exc)
                status = "timeout" if code == "llm_timeout" else "error"
                return build_result(status=status, completion_status=code, error=code)
            except Exception:
                return build_result(status="error", completion_status="llm_transport_error", error="llm_transport_error")

            if not isinstance(llm_response, LlmChatResponse) or llm_response.role != "assistant":
                return build_result(status="error", completion_status="llm_malformed_response", error="llm_invalid_role")
            if llm_response.finish_reason not in (None, "stop", "tool_calls", "length", "content_filter"):
                return build_result(status="error", completion_status="llm_malformed_response", error="llm_invalid_finish_reason")

            raw_calls = llm_response.tool_calls or ()
            if raw_calls and llm_response.finish_reason in {"length", "content_filter"}:
                return build_result(
                    status="incomplete",
                    completion_status="llm_response_incomplete",
                    assistant_text=llm_response.content if isinstance(llm_response.content, str) else None,
                    response_complete=False,
                    error="llm_response_incomplete",
                )
            if llm_response.finish_reason == "tool_calls" and not raw_calls:
                return build_result(status="error", completion_status="llm_malformed_response", error="llm_missing_tool_calls")

            if not raw_calls:
                if not isinstance(llm_response.content, str):
                    return build_result(status="error", completion_status="llm_malformed_response", error="llm_missing_content")
                if llm_response.finish_reason != "stop":
                    return build_result(
                        status="incomplete",
                        completion_status="llm_response_incomplete",
                        assistant_text=llm_response.content,
                        response_complete=False,
                        error="llm_response_incomplete",
                    )
                return build_result(
                    status="completed",
                    completion_status="completed",
                    assistant_text=llm_response.content,
                    response_complete=True,
                )

            assistant_tool_payloads: list[dict[str, Any]] = []
            tool_messages: list[dict[str, str]] = []
            for call in raw_calls:
                validated, reject_reason, raw_arg_digest = self._validate_proposed_tool_call(
                    call, tool_map=tool_map, seen_tool_call_ids=seen_tool_call_ids,
                )
                safe_call_id = _safe_id_or_none(call.id)
                safe_name = _safe_name_or_none(call.name)
                emit(
                    kind="agent_tool_intent",
                    provenance="model_reported",
                    model_idx=model_idx,
                    tool_call_id=safe_call_id,
                    tool_name=safe_name,
                    arguments_sha256=raw_arg_digest,
                )
                if reject_reason is not None or validated is None:
                    rejected_count += 1
                    emit(
                        kind="rejected_tool_call", provenance="secagent_policy", model_idx=model_idx,
                        tool_call_id=None if reject_reason == "malformed_tool_call_id" else safe_call_id,
                        tool_name=safe_name,
                        arguments_sha256=validated[2] if validated is not None else raw_arg_digest,
                        request_status="rejected", reason=reject_reason,
                    )
                    return build_result(status="blocked", completion_status="tool_call_rejected", error=reject_reason)

                safe_call_id, parsed_args, canonical_args_sha256 = validated
                seen_tool_call_ids.add(safe_call_id)

                scope_claims = tuple(sorted((k, v) for k, v in parsed_args.items() if isinstance(v, str)))
                mcp_blocked = preflight("mcp_tool_call", tool_name=safe_name, tool_scope_claims=scope_claims)
                if mcp_blocked is not None:
                    rejected_count += 1
                    status, reason = mcp_blocked
                    emit(
                        kind="rejected_tool_call", provenance="secagent_policy", model_idx=model_idx,
                        tool_call_id=safe_call_id, tool_name=safe_name, arguments_sha256=canonical_args_sha256,
                        request_status="rejected", reason=reason,
                    )
                    return build_result(status=status, completion_status=reason, error=reason)

                invocation_id = uuid4().hex
                if invocation_id in dispatched_invocations:
                    return build_result(status="error", completion_status="duplicate_invocation_id", error="duplicate_invocation_id")
                dispatched_invocations.add(invocation_id)

                mcp_remaining = max(0.001, deadline - self._clock())
                mcp_timeout = min(config_snapshot.mcp_timeout_seconds, mcp_remaining)
                tool_calls_used += 1
                self.last_dispatched_tool_arguments[invocation_id] = (
                    safe_name,
                    canonical_args_sha256,
                    deepcopy(parsed_args),
                )
                emit(
                    kind="secagent_mcp_request",
                    provenance="secagent_request",
                    model_idx=model_idx,
                    tool_call_id=safe_call_id,
                    invocation_id=invocation_id,
                    tool_name=safe_name,
                    arguments_sha256=canonical_args_sha256,
                    request_status="dispatched",
                )
                try:
                    mcp_resp = self._mcp_client.call_tool(McpToolRequest(
                        endpoint=config_snapshot.mcp_endpoint,
                        tool_name=safe_name,
                        arguments=parsed_args,
                        request_id=invocation_id,
                        credential_env=config_snapshot.mcp_credential_env,
                        timeout_seconds=mcp_timeout,
                        max_response_bytes=config_snapshot.max_response_bytes,
                    ))
                except Exception:
                    emit(
                        kind="target_mcp_response", provenance="target_reported", model_idx=model_idx,
                        tool_call_id=safe_call_id, invocation_id=invocation_id, tool_name=safe_name,
                        arguments_sha256=canonical_args_sha256, response_status="error", target_reported_success=False,
                    )
                    return build_result(status="error", completion_status="mcp_transport_error", error="mcp_transport_error")

                if not isinstance(mcp_resp, McpToolResponse) or not mcp_resp.success or mcp_resp.content_text is None:
                    err_code = mcp_resp.error_code if isinstance(mcp_resp, McpToolResponse) and mcp_resp.error_code else "mcp_call_failed"
                    tgt_ok = mcp_resp.target_reported_success if isinstance(mcp_resp, McpToolResponse) else False
                    emit(
                        kind="target_mcp_response", provenance="target_reported", model_idx=model_idx,
                        tool_call_id=safe_call_id, invocation_id=invocation_id, tool_name=safe_name,
                        arguments_sha256=canonical_args_sha256, response_status=err_code,
                        target_reported_success=tgt_ok,
                    )
                    resp_status = "timeout" if err_code == "mcp_timeout" else "error"
                    return build_result(status=resp_status, completion_status=err_code, error=err_code)

                result_digest = sha256(mcp_resp.content_text.encode("utf-8", errors="replace")).hexdigest()
                emit(
                    kind="target_mcp_response",
                    provenance="target_reported",
                    model_idx=model_idx,
                    tool_call_id=safe_call_id,
                    invocation_id=invocation_id,
                    tool_name=safe_name,
                    arguments_sha256=canonical_args_sha256,
                    response_status="ok",
                    target_reported_success=mcp_resp.target_reported_success,
                    result_sha256=result_digest,
                )
                assistant_tool_payloads.append({
                    "id": safe_call_id,
                    "type": "function",
                    "function": {"name": safe_name, "arguments": call.arguments},
                })
                # Treat tool result strictly as untrusted data with role='tool'.
                tool_messages.append({
                    "role": "tool",
                    "tool_call_id": safe_call_id,
                    "content": mcp_resp.content_text,
                })

            messages.append({
                "role": "assistant",
                "content": llm_response.content if isinstance(llm_response.content, str) else None,
                "tool_calls": assistant_tool_payloads,
            })
            messages.extend(tool_messages)

    @staticmethod
    def _validate_proposed_tool_call(
        call: LlmToolCall,
        *,
        tool_map: dict[str, ReviewedToolSpec],
        seen_tool_call_ids: set[str],
    ) -> tuple[tuple[str, dict[str, Any], str] | None, str | None, str]:
        raw_arg_digest = _hash_raw_arguments(call.arguments)
        safe_call_id = _safe_id_or_none(call.id)
        if safe_call_id is None:
            return None, "malformed_tool_call_id", raw_arg_digest
        if safe_call_id in seen_tool_call_ids:
            return None, "duplicate_tool_call_id", raw_arg_digest
        safe_name = _safe_name_or_none(call.name)
        if safe_name is None or safe_name not in tool_map:
            return None, "unknown_tool", raw_arg_digest
        parsed_args, parse_err = _parse_strict_json_arguments(call.arguments)
        if parse_err is not None or parsed_args is None:
            return None, parse_err or "invalid_argument_json", raw_arg_digest
        canonical_args_sha256 = sha256(
            json.dumps(parsed_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        schema_err = _validate_value_against_schema(parsed_args, tool_map[safe_name].input_schema)
        if schema_err is not None:
            return (safe_call_id, parsed_args, canonical_args_sha256), schema_err, raw_arg_digest
        return (safe_call_id, parsed_args, canonical_args_sha256), None, raw_arg_digest

    @staticmethod
    def _redact_secrets(text: str | None, config: McpAgentRuntimeConfig) -> str | None:
        if text is None:
            return None
        redacted = text
        for env_name in (config.credential_env, config.mcp_credential_env):
            if env_name:
                val = os.environ.get(env_name)
                if val:
                    redacted = redacted.replace(val, "[REDACTED]")
        return redacted
