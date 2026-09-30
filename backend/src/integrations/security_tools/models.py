"""Normalized models for external security tool integrations."""

from typing import Any

from pydantic import BaseModel, Field


class ExternalToolResult(BaseModel):
    """Normalized result returned by an external security tool provider."""

    tool_name: str = Field(min_length=1)
    success: bool
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    error: str | None = None
    artifacts: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
