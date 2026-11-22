"""Closed, secret-free HTTP preset and draft contracts."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}$")]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Preset(ClosedModel):
    id: Identifier
    name: Annotated[str, StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9 ._-]+$")]
    platform_id: Identifier | None = None
    platform_name: Annotated[str, StringConstraints(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9 ._-]+$")] | None = None
    reviewed: bool = False
    endpoint: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    protocol: Literal["openai-chat", "mcp-jsonrpc"] = "openai-chat"
    models: list[ModelName] = Field(min_length=1, max_length=20)
    default_model: ModelName
    timeout_min: int = Field(default=1, ge=1, le=120)
    timeout_max: int = Field(default=60, ge=1, le=120)
    timeout_default: int = Field(default=30, ge=1, le=120)
    credential_alias: Identifier | None = None

    @model_validator(mode="after")
    def coherent(self):
        if (self.platform_id is None) != (self.platform_name is None):
            raise ValueError("Platform ID and display name must be supplied together.")
        if self.default_model not in self.models or len(set(self.models)) != len(self.models):
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
    protocol: Literal["openai-chat", "mcp-jsonrpc"]
    method: Literal["POST"]
    model: ModelName
    request_mapping: Literal["openai-chat-user-message-v1", "mcp-tools-call-v1"]
    response_parser: Literal["choices.0.message.content", "mcp-jsonrpc-result-v1"]
    timeout_seconds: int = Field(ge=1, le=120)
    credential_alias: Identifier | None

    @model_validator(mode="after")
    def coherent_protocol(self):
        expected = (("openai-chat-user-message-v1", "choices.0.message.content")
                    if self.protocol == "openai-chat" else
                    ("mcp-tools-call-v1", "mcp-jsonrpc-result-v1"))
        if (self.request_mapping, self.response_parser) != expected:
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
