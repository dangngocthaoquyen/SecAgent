"""Closed, secret-free HTTP preset and draft contracts."""
import json
import math
import re
from typing import Annotated, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")]
DottedPath = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,63}){0,7}$"),
]
CapabilityStateLiteral = Literal["supported", "unsupported", "unverified"]
CapabilityProvenanceLiteral = Literal["operator_declared", "discovery_suggested", "runtime_confirmed"]
DeclarableCapabilityProvenanceLiteral = Literal["operator_declared", "discovery_suggested"]

_FORBIDDEN_CUSTOM_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key"})
_UNRESOLVED_REQUIRED_RE = re.compile(r"<REQUIRED:[A-Za-z0-9_.-]+>")


def _has_unresolved_placeholder(value: Any, *, depth: int = 0) -> bool:
    if depth > 12:
        return True
    if isinstance(value, str):
        return _UNRESOLVED_REQUIRED_RE.search(value) is not None
    if isinstance(value, list):
        return any(_has_unresolved_placeholder(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return any(
            (isinstance(k, str) and _UNRESOLVED_REQUIRED_RE.search(k) is not None)
            or _has_unresolved_placeholder(v, depth=depth + 1)
            for k, v in value.items()
        )
    return False


def _contains_input_placeholder(value: Any, *, depth: int = 0) -> bool:
    if depth > 12:
        raise ValueError("Request body template exceeds maximum nesting depth.")
    if isinstance(value, str):
        return "{{input}}" in value
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return False
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Nonfinite float in request body template.")
        return False
    if isinstance(value, list):
        if len(value) > 50:
            raise ValueError("Request body template list exceeds size bound.")
        return any(_contains_input_placeholder(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        if len(value) > 50:
            raise ValueError("Request body template object exceeds key bound.")
        found = False
        for k, v in value.items():
            if not isinstance(k, str) or not k or len(k) > 128:
                raise ValueError("Invalid key in request body template.")
            if _contains_input_placeholder(v, depth=depth + 1):
                found = True
        return found
    raise ValueError("Unsupported value type in request body template.")


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class HttpInlineEvidenceMapping(ClosedModel):
    items: str = Field(default="", max_length=256)
    event_id: DottedPath | None = None
    action: DottedPath | None = None
    arguments: DottedPath | None = None
    decision: DottedPath | None = None
    status: DottedPath | None = None
    observation: DottedPath | None = None
    timestamp: DottedPath | None = None
    max_events: int = Field(default=50, ge=1, le=50)

    @field_validator("items")
    @classmethod
    def valid_items(cls, value: str) -> str:
        if value != "" and not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,63}){0,7}",
            value,
        ):
            raise ValueError("Use bounded dotted path for evidence items.")
        return value


class HttpResponseContract(ClosedModel):
    text_path: DottedPath
    status_path: DottedPath | None = None
    complete_status_values: list[Annotated[str, StringConstraints(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=12
    )
    incomplete_status_values: list[Annotated[str, StringConstraints(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=12
    )
    correlation_id_path: DottedPath | None = None
    evidence_mapping: HttpInlineEvidenceMapping | None = None


class HttpContractConfig(ClosedModel):
    method: Literal["POST"] = "POST"
    body_template: dict[str, Any]
    headers: dict[str, str] = Field(default_factory=dict, max_length=16)
    response: HttpResponseContract

    @model_validator(mode="after")
    def validate_template(self):
        encoded = json.dumps(self.body_template, sort_keys=True, ensure_ascii=False).encode("utf-8")
        if len(encoded) > 16384:
            raise ValueError("Request body template exceeds 16 KiB limit.")
        if not _contains_input_placeholder(self.body_template):
            raise ValueError("Request body template must contain '{{input}}'.")
        if _has_unresolved_placeholder(self.body_template):
            raise ValueError("Unresolved discovery required placeholders must be resolved before saving.")
        for key, val in self.headers.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key):
                raise ValueError("Invalid HTTP header name.")
            if key.lower() in _FORBIDDEN_CUSTOM_HEADERS:
                raise ValueError("Use credential_alias for secret authentication headers.")
            if "{{" in val or "}}" in val or _UNRESOLVED_REQUIRED_RE.search(val) or len(val) > 256 or any(ord(c) < 32 for c in val):
                raise ValueError("Invalid HTTP header value.")
        return self


class Preset(ClosedModel):
    id: Identifier
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._-]+$")]
    platform_id: Identifier | None = None
    platform_name: Annotated[str, StringConstraints(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._-]+$")] | None = None
    reviewed: bool = False
    endpoint: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    protocol: Literal["openai-chat", "http-json", "mcp-jsonrpc"] = "openai-chat"
    models: list[ModelName] = Field(default_factory=list, max_length=20)
    default_model: ModelName | None = None
    timeout_min: int = Field(default=1, ge=1, le=120)
    timeout_max: int = Field(default=60, ge=1, le=120)
    timeout_default: int = Field(default=30, ge=1, le=120)
    credential_alias: Identifier | None = None
    http_config: HttpContractConfig | None = None
    capability_states: dict[Identifier, CapabilityStateLiteral] | None = None
    capability_provenance: dict[Identifier, CapabilityProvenanceLiteral] | None = None

    @model_validator(mode="after")
    def coherent(self):
        if (self.platform_id is None) != (self.platform_name is None):
            raise ValueError("Platform ID and display name must be supplied together.")
        if self.protocol == "http-json":
            if self.http_config is None:
                raise ValueError("http-json protocol requires http_config.")
            if self.default_model is not None and self.default_model not in self.models:
                raise ValueError("Invalid model choices.")
            if len(set(self.models)) != len(self.models):
                raise ValueError("Duplicate model choices.")
        else:
            if self.http_config is not None:
                raise ValueError("http_config is only valid for http-json protocol.")
            if not self.models or self.default_model is None or self.default_model not in self.models or len(set(self.models)) != len(self.models):
                raise ValueError("Invalid model choices.")
        if not self.timeout_min <= self.timeout_default <= self.timeout_max:
            raise ValueError("Invalid timeout bounds.")
        return self


class CatalogConfig(ClosedModel):
    catalog_schema_version: Literal["1.0.0"]
    policy_ref: Identifier
    credential_aliases: dict[Identifier, Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]] = Field(default_factory=dict, max_length=50)
    targets: list[Preset] = Field(max_length=50)

    @model_validator(mode="after")
    def unique(self):
        if len({p.id for p in self.targets}) != len(self.targets):
            raise ValueError("Duplicate target identity.")
        platform_names = {}
        for preset in self.targets:
            if preset.platform_id is not None:
                previous = platform_names.setdefault(preset.platform_id, preset.platform_name)
                if previous != preset.platform_name:
                    raise ValueError("Conflicting platform display names.")
        if any(p.credential_alias is not None and p.credential_alias not in self.credential_aliases for p in self.targets):
            raise ValueError("Unregistered credential alias.")
        return self


class TargetDraft(ClosedModel):
    target_id: Identifier
    profile_revision: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    policy_ref: Identifier
    endpoint: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    protocol: Literal["openai-chat", "http-json", "mcp-jsonrpc"]
    method: Literal["POST"]
    model: ModelName | None = None
    request_mapping: Literal["openai-chat-user-message-v1", "http-json-template-v1", "mcp-tools-call-v1"]
    response_parser: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    timeout_seconds: int = Field(ge=1, le=120)
    credential_alias: Identifier | None

    @model_validator(mode="after")
    def coherent_protocol(self):
        if self.protocol == "openai-chat":
            if (self.request_mapping, self.response_parser) != ("openai-chat-user-message-v1", "choices.0.message.content") or self.model is None:
                raise ValueError("Protocol, request mapping and response parser differ.")
        elif self.protocol == "mcp-jsonrpc":
            if (self.request_mapping, self.response_parser) != ("mcp-tools-call-v1", "mcp-jsonrpc-result-v1") or self.model is None:
                raise ValueError("Protocol, request mapping and response parser differ.")
        else:
            if self.request_mapping != "http-json-template-v1" or not re.fullmatch(
                r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,63}){0,7}$",
                self.response_parser,
            ):
                raise ValueError("Protocol, request mapping and response parser differ.")
        return self


class ConnectionCheckRequest(ClosedModel):
    target_id: Identifier
    profile_revision: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    policy_ref: Identifier


class ConnectionCheckResult(ClosedModel):
    workflow_schema_version: Literal["1.0.0"] = "1.0.0"
    connection_status: Literal["requires_approval", "rejected", "unsupported", "succeeded", "incompatible", "unavailable"]
    reason: Identifier
    target_request_count: Literal[0, 1] = 0
    connection_reachable: bool | None = None
    runtime_protocol_compatible: bool | None = None
    http_status: int | None = None
    security_test_executed: Literal[False] = False
    security_verdict: None = None
