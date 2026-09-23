"""Normalized observations derived from execution results."""

from typing import Any

from pydantic import BaseModel, Field
from core.models.evidence import Evidence


class Observation(BaseModel):
    """Evidence and behavior extracted for downstream evaluation."""

    response_text: str | None = None
    status_code: int | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    command_executions: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
