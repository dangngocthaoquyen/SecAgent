"""Normalized result produced after executing a test against a target."""

from typing import Any

from pydantic import BaseModel, Field

EXPLICIT_TRUNCATION_FINISH_REASONS: frozenset[str] = frozenset({
    "length",
    "max_tokens",
    "content_filter",
})

NON_COMPLETION_FINISH_REASONS: frozenset[str] = frozenset({
    "tool_calls",
    "function_call",
})


def resolve_response_completeness(
    *,
    finish_reason: str | None = None,
    explicit_response_complete: bool | None = None,
    body_complete: bool | None = None,
    has_output_text: bool = True,
    response_only_completion: bool = True,
    has_choices_envelope: bool = False,
    is_json_dict: bool = True,
    is_offline: bool = False,
    truncated_flag: bool | None = None,
) -> bool | None:
    """Resolve tri-state target-reported response text completeness (True / False / None).

    Completion semantics:
    - True: Target/transport reported normal response-text completion. Never implies
      agent execution completion, tool execution, or complete runtime trace.
    - False: Explicit incompleteness/truncation (incomplete HTTP body, explicit
      response_complete=False, truncated=True, or finish_reason in
      {"length", "max_tokens", "content_filter"}).
    - None: Unknown/unverified completeness (e.g., missing/unknown finish_reason,
      tool_calls/function_call stop, or response_only_completion=False).
    """
    if body_complete is False or truncated_flag is True or explicit_response_complete is False:
        return False

    normalized_reason = (
        finish_reason.strip().lower()
        if isinstance(finish_reason, str) and finish_reason.strip()
        else None
    )
    if normalized_reason in EXPLICIT_TRUNCATION_FINISH_REASONS:
        return False

    if explicit_response_complete is True:
        return True if (has_output_text and response_only_completion) else None

    if not response_only_completion or not has_output_text:
        return None

    if normalized_reason == "stop":
        return True

    if normalized_reason is not None:
        # Includes "tool_calls", "function_call", and any unknown vendor finish_reason.
        return None

    # finish_reason is None:
    if is_offline or has_choices_envelope or not is_json_dict:
        return None

    # Non-choices custom JSON response with a complete HTTP body and extracted output text.
    if body_complete is True:
        return True

    return None


class ExecutionResult(BaseModel):
    """Target-agnostic raw execution result."""

    success: bool
    status_code: int | None = None
    output_text: str | None = None
    # Explicit target/transport-reported response-text completion (True/False/None).
    # Never implies agent execution completion or internal tool-trace completeness.
    response_complete: bool | None = Field(default=None, strict=True)
    raw_output: Any = None
    headers: dict[str, str] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: float | None = Field(default=None, ge=0)
    error: str | None = None
