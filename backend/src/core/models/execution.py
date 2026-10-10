"""Normalized result produced after executing a test against a target."""

from typing import Any

from pydantic import BaseModel, Field


class ExecutionResult(BaseModel):
    """Target-agnostic raw execution result."""

    success: bool
    status_code: int | None = None
    output_text: str | None = None
    # Explicit caller/adapter assurance about the target answer, not HTTP status
    # or internal tool-trace completeness. Generic HTTP leaves this unknown.
    response_complete: bool | None = Field(default=None, strict=True)
    raw_output: Any = None
    headers: dict[str, str] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: float | None = Field(default=None, ge=0)
    error: str | None = None
