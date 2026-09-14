"""Models describing a target and the interface used to reach it."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TargetInterface(BaseModel):
    """Connection details required by a target adapter."""

    model_config = ConfigDict(extra="forbid")

    type: str
    adapter: str
    config: dict[str, Any] = Field(default_factory=dict)


class TargetProfile(BaseModel):
    """Generic description of a target under test."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    target_type: str
    interface: TargetInterface
    capabilities: list[str] = Field(default_factory=list)
    observability: list[str] = Field(default_factory=list)
    credential_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
