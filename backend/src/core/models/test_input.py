"""Model for target-agnostic test input."""

from typing import Any

from pydantic import BaseModel, Field


class TestInput(BaseModel):
    """Input and optional references supplied to a target execution."""

    id: str
    prompt: str | None = None
    payload_ref: str | None = None
    artifact_refs: list[str] = Field(default_factory=list)
    file_refs: list[str] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
