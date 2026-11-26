"""Strict, fail-closed parser for untrusted LLM generation output (G11.3B).

Treats `ProviderGenerationResponse.raw_text` as untrusted input:
- Enforces UTF-8 byte ceiling and iterative JSON nesting depth ceiling before decoding.
- Rejects Markdown code fences, prose wrappers, trailing data, duplicate JSON keys,
  and non-standard constants (`NaN`, `Infinity`, `-Infinity`).
- Requires an explicit top-level `candidates` array key, clearly distinguishing
  missing `candidates` from explicit `candidates: []`.
- Explicitly detects and rejects authority-escalating keys (`FORBIDDEN_LLM_OUTPUT_KEYS`).
- Validates final structure strictly via `RawGenerationOutputContract`.
- Never echoes raw LLM response content into error messages or logs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import ValidationError

from generator.constants import FORBIDDEN_LLM_OUTPUT_KEYS
from generator.models import RawGenerationOutputContract, StrictGeneratorModel

DEFAULT_MAX_RAW_OUTPUT_BYTES: int = 256 * 1024  # 256 KiB
DEFAULT_MAX_JSON_DEPTH: int = 16
MAX_VALIDATION_ERROR_SUMMARY_CHARS: int = 320

_TRUSTED_SCHEMA_FIELD_NAMES: frozenset[str] = frozenset({
    "schema_version",
    "asi_category",
    "context_gaps",
    "candidates",
    "prompt",
    "description",
    "strategy_tag",
    "context_basis",
    "scope_note",
})
_SAFE_ERROR_TYPE_RE = re.compile(r"^[a-z0-9_]{1,48}$")

OutputParseErrorCode = Literal[
    "truncated_output",
    "empty_output",
    "oversized_output",
    "non_json_wrapper",
    "malformed_json",
    "invalid_json_constant",
    "duplicate_json_key",
    "json_depth_exceeded",
    "non_object_root",
    "missing_candidates_key",
    "candidates_wrong_type",
    "authority_field_rejected",
    "schema_validation_failed",
]


class OutputParseError(ValueError):
    """Secret-free, structured parse/validation error for untrusted LLM output."""

    def __init__(self, code: OutputParseErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: OutputParseErrorCode = code
        self.message: str = message


class ParsedGenerationOutput(StrictGeneratorModel):
    """Strictly parsed and schema-verified LLM output contract with byte metadata."""

    contract: RawGenerationOutputContract
    raw_bytes: int


class _DuplicateKeyError(Exception):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


class _InvalidConstantError(Exception):
    def __init__(self, constant: str) -> None:
        super().__init__(constant)
        self.constant = constant


def _check_json_nesting_depth(text: str, *, max_depth: int) -> None:
    """Iteratively verify JSON nesting depth without risking recursion overflow."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                raise OutputParseError(
                    "json_depth_exceeded",
                    f"LLM JSON output exceeds maximum nesting depth of {max_depth}.",
                )
        elif ch in "}]":
            depth = max(0, depth - 1)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKeyError(key)
        obj[key] = value
    return obj


def _reject_json_constant(constant: str) -> Any:
    raise _InvalidConstantError(constant)


def _find_forbidden_authority_key(value: Any) -> str | None:
    """Iteratively scan parsed JSON structures for authority-escalating keys."""
    stack: list[Any] = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, nested in current.items():
                if isinstance(key, str) and key in FORBIDDEN_LLM_OUTPUT_KEYS:
                    return key
                if isinstance(nested, (dict, list)):
                    stack.append(nested)
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append(item)
    return None


def _sanitize_loc_segment(segment: Any) -> str:
    """Emit only trusted schema field names or bounded array indices; mask untrusted keys."""
    if isinstance(segment, int) and not isinstance(segment, bool) and 0 <= segment <= 9999:
        return str(segment)
    if isinstance(segment, str) and segment in _TRUSTED_SCHEMA_FIELD_NAMES:
        return segment
    return "<unexpected_field>"


def _sanitize_error_type(raw_type: Any) -> str:
    if isinstance(raw_type, str) and _SAFE_ERROR_TYPE_RE.fullmatch(raw_type):
        return raw_type
    return "validation_error"


def _summarize_validation_error(exc: ValidationError) -> str:
    """Build a bounded, secret-free summary using only trusted schema field names."""
    parts: list[str] = []
    errors = exc.errors()
    for err in errors[:5]:
        raw_loc = err.get("loc", ())
        safe_segments = [_sanitize_loc_segment(segment) for segment in raw_loc]
        loc = ".".join(safe_segments) if safe_segments else "<root>"
        err_type = _sanitize_error_type(err.get("type"))
        parts.append(f"{loc} ({err_type})")
    suffix = " ..." if len(errors) > 5 else ""
    summary = (
        "LLM output failed RawGenerationOutputContract validation: "
        + "; ".join(parts)
        + suffix
        + "."
    )
    if len(summary) > MAX_VALIDATION_ERROR_SUMMARY_CHARS:
        summary = summary[: MAX_VALIDATION_ERROR_SUMMARY_CHARS - 3].rstrip() + "..."
    return summary


def parse_llm_generation_output(
    raw_text: str | None,
    *,
    finish_reason: str | None = None,
    max_raw_bytes: int = DEFAULT_MAX_RAW_OUTPUT_BYTES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> ParsedGenerationOutput:
    """Strictly parse and validate untrusted LLM JSON output into RawGenerationOutputContract.

    Raises OutputParseError with a normalized error code and secret-free message on any
    violation. Never invokes eval, never repairs broken JSON, and never logs raw content.
    """
    if isinstance(max_raw_bytes, bool) or not isinstance(max_raw_bytes, int) or max_raw_bytes < 64:
        raise ValueError("max_raw_bytes must be an integer >= 64.")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 2:
        raise ValueError("max_depth must be an integer >= 2.")

    if isinstance(finish_reason, str) and finish_reason.strip().lower() == "length":
        raise OutputParseError(
            "truncated_output",
            "LLM generation output was truncated before completion (finish_reason=length).",
        )

    if not isinstance(raw_text, str) or not raw_text.strip():
        raise OutputParseError(
            "empty_output",
            "LLM generation output is empty.",
        )

    raw_bytes = len(raw_text.encode("utf-8"))
    if raw_bytes > max_raw_bytes:
        raise OutputParseError(
            "oversized_output",
            f"LLM generation output ({raw_bytes} bytes) exceeds maximum limit of {max_raw_bytes} bytes.",
        )

    stripped = raw_text.strip()
    if stripped.startswith("```") or stripped.endswith("```"):
        raise OutputParseError(
            "non_json_wrapper",
            "LLM generation output contains Markdown code fences; a single raw JSON object is required.",
        )

    # Check nesting depth iteratively before any json decoding to prevent recursion blowup.
    _check_json_nesting_depth(stripped, max_depth=max_depth)

    # Detect prose wrapper around a JSON object before full decode.
    if not stripped.startswith("{") and "{" in stripped and not stripped.startswith("["):
        try:
            json.loads(stripped, parse_constant=_reject_json_constant)
        except Exception:
            raise OutputParseError(
                "non_json_wrapper",
                "LLM generation output contains non-JSON text outside the JSON document.",
            ) from None

    if stripped.startswith("{") and not stripped.endswith("}"):
        # Distinguish trailing commentary/wrapper vs truncated/malformed JSON.
        try:
            _, end_idx = json.JSONDecoder(
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            ).raw_decode(stripped)
        except _DuplicateKeyError:
            raise OutputParseError(
                "duplicate_json_key",
                "LLM JSON output contains duplicate object keys.",
            ) from None
        except _InvalidConstantError:
            raise OutputParseError(
                "invalid_json_constant",
                "LLM JSON output contains non-standard numeric constants (NaN/Infinity).",
            ) from None
        except (json.JSONDecodeError, ValueError):
            raise OutputParseError(
                "malformed_json",
                "LLM generation output is not valid JSON or exceeds safe numeric bounds.",
            ) from None
        if end_idx < len(stripped):
            raise OutputParseError(
                "non_json_wrapper",
                "LLM generation output contains trailing non-JSON content after the JSON object.",
            )

    try:
        parsed = json.loads(
            stripped,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError:
        raise OutputParseError(
            "duplicate_json_key",
            "LLM JSON output contains duplicate object keys.",
        ) from None
    except _InvalidConstantError:
        raise OutputParseError(
            "invalid_json_constant",
            "LLM JSON output contains non-standard numeric constants (NaN/Infinity).",
        ) from None
    except (json.JSONDecodeError, ValueError):
        raise OutputParseError(
            "malformed_json",
            "LLM generation output is not valid JSON or exceeds safe numeric bounds.",
        ) from None

    if not isinstance(parsed, dict):
        raise OutputParseError(
            "non_object_root",
            "LLM JSON output root must be a JSON object.",
        )

    # Reject authority-escalating keys explicitly before schema validation.
    forbidden_key = _find_forbidden_authority_key(parsed)
    if forbidden_key is not None:
        raise OutputParseError(
            "authority_field_rejected",
            f"LLM JSON output attempted to emit forbidden authority field '{forbidden_key}'.",
        )

    # Explicitly require top-level `candidates` key (distinguish missing vs empty list `[]`).
    if "candidates" not in parsed:
        raise OutputParseError(
            "missing_candidates_key",
            "LLM JSON output is missing the required top-level 'candidates' key.",
        )

    if not isinstance(parsed["candidates"], list):
        raise OutputParseError(
            "candidates_wrong_type",
            "LLM JSON output top-level 'candidates' value must be a JSON array.",
        )

    try:
        contract = RawGenerationOutputContract.model_validate(parsed)
    except ValidationError as exc:
        raise OutputParseError(
            "schema_validation_failed",
            _summarize_validation_error(exc),
        ) from None

    return ParsedGenerationOutput(contract=contract, raw_bytes=raw_bytes)
