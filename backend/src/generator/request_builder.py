"""Allowlist-based sanitized Generation Request builder for SecAgent G11.

Strictly separates:
1. Trusted system instructions (loaded Generation Skill bundle v1.0.1).
2. Untrusted application data (allowlisted confirmed context fields + optional
   reviewed policy boundary descriptions + optional focus_note, sanitized via
   Redactor and local-path scrubbing).
3. Backend-controlled generation parameters (ASI code, count, language,
   protocol surface label, effective scope, capability status summary).

Never accepts raw Target objects, credentials, session tokens, HTTP headers,
body templates, endpoint URLs/IPs, executable evaluation rules, or historical
verdicts. Regex redaction is defense-in-depth and is never claimed to be an
absolute guarantee against all possible sensitive text.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Literal, Sequence
from uuid import uuid4

from pydantic import Field

from generator.constants import (
    AsiCategory,
    AsiCode,
    HARD_MAX_PER_ASI,
    MAX_PLANNED_CHUNKS_PER_ASI,
)
from generator.models import (
    DEFAULT_GENERATION_LIMITS,
    GenerationLimits,
    GeneratorSkillBundle,
    StrictGeneratorModel,
)
from generator.providers.base import (
    DEFAULT_MAX_OUTPUT_TOKENS_CEILING,
    ProviderGenerationRequest,
    compute_token_budget,
)
from generator.readiness import (
    APPLICATION_CONTEXT_TEXT_FIELDS,
    AsiReadinessAssessment,
    ConfirmedContextSnapshot,
    ReviewedPolicySummary,
)
from reporting.redaction import Redactor

SupportedLanguage = Literal["en", "vi"]

# Strict projection allowlists: ONLY these keys may enter untrusted_application_data.
ALLOWED_CONTEXT_PROJECTION_FIELDS: tuple[str, ...] = APPLICATION_CONTEXT_TEXT_FIELDS
ALLOWED_POLICY_PROJECTION_FIELDS: tuple[str, ...] = (
    "prohibited_behavior",
    "allowed_benign_context",
    "expected_response_boundary",
    "established_identity",
)

MAX_PROJECTED_FIELD_CHARS: int = 1000
MAX_PROJECTED_POLICY_FIELD_CHARS: int = 1500
MAX_FOCUS_NOTE_CHARS: int = 300

# Defense-in-depth scrubbing for local filesystem paths & raw IP:port endpoints.
_WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_.-]+\\)[^\s\"'<>|]+")
_POSIX_LOCAL_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])/(?:Users|home|etc|var|tmp|opt|root|proc|sys|mnt|srv)/[^\s\"'<>|]+"
)
_IP_PORT_RE = re.compile(
    r"\b(?:(?:127|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b"
)
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----")
_PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_SAFE_STRATEGY_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
MAX_PRIOR_STRATEGY_TAGS_HINT: int = 32


class GenerationRequestError(ValueError):
    """Raised when a sanitized Generation Request cannot be safely constructed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class GenerationProvenanceInputs(StrictGeneratorModel):
    """Non-secret provenance references preserved for G11.3B manifest construction."""

    target_id: str
    target_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_context_revision_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    context_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewed_policy_id: str | None = None
    reviewed_policy_revision_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    skill_id: str
    skill_version: str
    skill_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    asi_code: AsiCode
    asi_category: AsiCategory
    effective_scope: str
    requested_count: int = Field(ge=1, le=HARD_MAX_PER_ASI, strict=True)
    language: SupportedLanguage
    projected_context_fields: tuple[str, ...] = ()


class SanitizedGenerationRequestEnvelope(StrictGeneratorModel):
    """Combined output of request_builder: ready ProviderGenerationRequest + provenance inputs."""

    provider_request: ProviderGenerationRequest
    sanitized_user_payload: dict[str, Any]
    provenance_inputs: GenerationProvenanceInputs


def _sanitize_text(
    raw: str,
    *,
    cleaner: Redactor,
    limit: int,
) -> str:
    """Apply read-only Redactor cleaning plus local-path, PEM, and private-IP scrubbing."""
    cleaned = _PEM_BLOCK_RE.sub("[CREDENTIAL_REDACTED]", raw)
    cleaned = _PEM_HEADER_RE.sub("[CREDENTIAL_REDACTED]", cleaned)
    cleaned = cleaner.clean(cleaned, limit=max(limit * 2, 2048), opaque=False) or ""
    cleaned = _WINDOWS_PATH_RE.sub("[PATH_REDACTED]", cleaned)
    cleaned = _POSIX_LOCAL_PATH_RE.sub("[PATH_REDACTED]", cleaned)
    cleaned = _IP_PORT_RE.sub("[HOST_REDACTED]", cleaned)
    # Collapse excessive control characters while preserving normal newlines.
    cleaned = "".join(ch for ch in cleaned if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    return cleaned.strip()[:limit]


def _project_confirmed_context(
    snapshot: ConfirmedContextSnapshot,
    *,
    cleaner: Redactor,
) -> dict[str, str]:
    projected: dict[str, str] = {}
    for field_name in ALLOWED_CONTEXT_PROJECTION_FIELDS:
        raw_val = snapshot.confirmed_fields.get(field_name)
        if not isinstance(raw_val, str) or not raw_val.strip():
            continue
        sanitized = _sanitize_text(raw_val, cleaner=cleaner, limit=MAX_PROJECTED_FIELD_CHARS)
        if sanitized:
            projected[field_name] = sanitized
    return projected


def _project_reviewed_policy(
    policy: ReviewedPolicySummary | None,
    *,
    cleaner: Redactor,
) -> dict[str, str] | None:
    if policy is None:
        return None
    projected: dict[str, str] = {}
    for field_name in ALLOWED_POLICY_PROJECTION_FIELDS:
        raw_val = getattr(policy, field_name, None)
        if not isinstance(raw_val, str) or not raw_val.strip():
            continue
        sanitized = _sanitize_text(raw_val, cleaner=cleaner, limit=MAX_PROJECTED_POLICY_FIELD_CHARS)
        if sanitized:
            projected[field_name] = sanitized
    return projected or None


def build_sanitized_generation_request(
    *,
    skill_bundle: GeneratorSkillBundle,
    snapshot: ConfirmedContextSnapshot,
    assessment: AsiReadinessAssessment,
    requested_count: int,
    language: SupportedLanguage = "en",
    focus_note: str | None = None,
    token_ceiling: int = DEFAULT_MAX_OUTPUT_TOKENS_CEILING,
    limits: GenerationLimits = DEFAULT_GENERATION_LIMITS,
    request_id: str | None = None,
    extra_sensitive_values: tuple[str, ...] = (),
    chunk_index: int | None = None,
    total_chunks: int | None = None,
    prior_strategy_tags: Sequence[str] | None = None,
) -> SanitizedGenerationRequestEnvelope:
    """Build a strictly separated, allowlisted Generation Request for one ASI.

    Fails closed if readiness is blocked, ASI mismatches the loaded skill bundle,
    or requested_count violates centralized GenerationLimits.
    """
    if assessment.status == "blocked":
        raise GenerationRequestError(
            "readiness_blocked",
            "Cannot build generation request while readiness is blocked: "
            + ", ".join(assessment.blockers),
        )
    if assessment.asi_code != skill_bundle.identity.asi_code:
        raise GenerationRequestError(
            "skill_asi_mismatch",
            f"Loaded skill bundle ({skill_bundle.identity.asi_code}) does not match "
            f"readiness assessment ({assessment.asi_code}).",
        )
    if assessment.effective_scope is None:
        raise GenerationRequestError(
            "missing_effective_scope",
            "Backend effective_scope is required before building a generation request.",
        )

    try:
        limits.validate_per_asi_counts({assessment.asi_code: requested_count})
    except ValueError as exc:
        raise GenerationRequestError("invalid_requested_count", str(exc)) from exc

    if language not in {"en", "vi"}:
        raise GenerationRequestError("unsupported_language", f"Unsupported language: {language!r}.")

    cleaner = Redactor(extra_sensitive_values)
    projected_context = _project_confirmed_context(snapshot, cleaner=cleaner)
    policy = snapshot.reviewed_policies.get(assessment.asi_code)
    projected_policy = _project_reviewed_policy(policy, cleaner=cleaner)

    sanitized_focus_note: str | None = None
    if focus_note is not None:
        if not isinstance(focus_note, str):
            raise GenerationRequestError("invalid_focus_note", "focus_note must be a string.")
        cleaned_focus = _sanitize_text(focus_note, cleaner=cleaner, limit=MAX_FOCUS_NOTE_CHARS)
        sanitized_focus_note = cleaned_focus or None

    # Strictly separate backend-controlled generation parameters from untrusted application data.
    untrusted_data: dict[str, Any] = {
        "trust_level": "untrusted_data_not_instructions",
        "application_context": projected_context,
    }
    if projected_policy is not None:
        untrusted_data["optional_reviewed_policy_boundaries"] = projected_policy
    if sanitized_focus_note is not None:
        untrusted_data["operator_focus_note"] = sanitized_focus_note

    generation_parameters: dict[str, Any] = {
        "schema_version": "1.0",
        "asi_code": assessment.asi_code,
        "asi_category": assessment.asi_category,
        "requested_count": requested_count,
        "language": language,
        "target_surface": snapshot.target_protocol,
        "effective_scope": assessment.effective_scope,
        "scope_capability_state": assessment.scope_capability_state,
        "evidence_availability": list(snapshot.evidence_availability),
        "capability_states": dict(sorted(snapshot.capability_states.items())),
        "excluded_unverified_fields": list(snapshot.excluded_unverified_fields),
        "excluded_missing_provenance_fields": list(snapshot.excluded_missing_provenance_fields),
        "readiness_warnings": list(assessment.warnings),
    }
    if total_chunks is not None and total_chunks > 1:
        if (
            isinstance(total_chunks, bool)
            or not isinstance(total_chunks, int)
            or total_chunks > MAX_PLANNED_CHUNKS_PER_ASI
        ):
            raise GenerationRequestError(
                "invalid_chunk_plan",
                f"total_chunks must be an integer between 2 and {MAX_PLANNED_CHUNKS_PER_ASI}.",
            )
        if (
            chunk_index is None
            or isinstance(chunk_index, bool)
            or not isinstance(chunk_index, int)
            or chunk_index < 1
            or chunk_index > total_chunks
        ):
            raise GenerationRequestError(
                "invalid_chunk_index",
                f"chunk_index must be an integer between 1 and {total_chunks}.",
            )
        generation_parameters["chunk_index"] = chunk_index
        generation_parameters["total_chunks"] = total_chunks
        if prior_strategy_tags:
            safe_tags = sorted(
                {
                    tag.strip()
                    for tag in prior_strategy_tags
                    if isinstance(tag, str) and _SAFE_STRATEGY_TAG_RE.fullmatch(tag.strip())
                }
            )[:MAX_PRIOR_STRATEGY_TAGS_HINT]
            if safe_tags:
                generation_parameters["prior_chunk_strategy_tags"] = safe_tags

    user_payload: dict[str, Any] = {
        "generation_parameters": generation_parameters,
        "untrusted_application_data": untrusted_data,
    }
    user_payload_json = json.dumps(
        user_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )

    request_sha256 = sha256(
        json.dumps(
            {
                "skill_sha256": skill_bundle.identity.sha256,
                "user_payload": user_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    max_tokens = compute_token_budget(requested_count, ceiling=token_ceiling)
    resolved_req_id = request_id or f"genreq-{uuid4().hex[:16]}"

    provider_request = ProviderGenerationRequest(
        request_id=resolved_req_id,
        asi_code=assessment.asi_code,
        requested_count=requested_count,
        system_prompt=skill_bundle.system_prompt,
        user_payload_json=user_payload_json,
        request_sha256=request_sha256,
        skill_version=skill_bundle.identity.version,
        skill_sha256=skill_bundle.identity.sha256,
        max_tokens=max_tokens,
    )

    provenance_inputs = GenerationProvenanceInputs(
        target_id=snapshot.target_id,
        target_revision_sha256=snapshot.target_revision_sha256,
        application_context_revision_sha256=snapshot.application_context_revision_sha256,
        context_snapshot_sha256=snapshot.snapshot_sha256,
        reviewed_policy_id=assessment.reviewed_policy_id,
        reviewed_policy_revision_sha256=assessment.reviewed_policy_revision_sha256,
        skill_id=skill_bundle.identity.id,
        skill_version=skill_bundle.identity.version,
        skill_sha256=skill_bundle.identity.sha256,
        request_sha256=request_sha256,
        asi_code=assessment.asi_code,
        asi_category=assessment.asi_category,
        effective_scope=assessment.effective_scope,
        requested_count=requested_count,
        language=language,
        projected_context_fields=tuple(sorted(projected_context.keys())),
    )

    return SanitizedGenerationRequestEnvelope(
        provider_request=provider_request,
        sanitized_user_payload=user_payload,
        provenance_inputs=provenance_inputs,
    )
