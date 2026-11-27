"""Stateless Context-aware Generator Service for SecAgent G11.3B.

Orchestrates G11.2 and G11.3A components end-to-end without contacting any Target,
calling any Judge/Evaluator, mutating any store, or persisting any dataset:
1. Validate centralized generation count limits (<= 50/ASI, <= 50/generation).
2. Read read-only Confirmed Context Snapshot and per-ASI Readiness (`assess_target_readiness`).
3. Skip/block blocked ASIs with zero provider calls and zero scope downgrade.
4. Load allowlisted Generation Skills (`GeneratorSkillLoader`).
5. Build allowlist-projected, sanitized provider request (`build_sanitized_generation_request`).
6. Invoke `GeneratorLLMProvider` within an explicit bounded call budget (default 1, max 2).
7. Strictly parse untrusted LLM output (`parse_llm_generation_output`).
8. Validate ASI consistency and confirmed `context_basis` (`validate_parsed_output`).
9. Deduplicate via exact/normalized text v1 (`deduplicate_asi_candidates`).
10. Mint backend-controlled ephemeral candidate IDs, classify empty/partial/completed/failed
    outcomes honestly, and return immutable provenance + statistics for G11.3C / G11.6.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import re
from threading import Event
from typing import Any, Literal, Mapping, Sequence
from uuid import uuid4

from pydantic import Field, field_validator

from core.cancellation import RunCancelledError
from generator.constants import (
    ASI_CODE_TO_CATEGORY,
    AsiCategory,
    AsiCode,
    DEFAULT_GENERATION_CHUNK_SIZE,
    DEFAULT_PER_ASI,
    HARD_MAX_PER_ASI,
    MAX_GENERATION_OUTPUT_TOKEN_BUDGET,
    MAX_GENERATION_TOTAL_PROVIDER_CALLS,
    MAX_PLANNED_CHUNKS_PER_ASI,
    MAX_TOTAL_PROVIDER_CALLS_PER_ASI,
    SUPPORTED_ASI_CODES,
)
from generator.deduplication import (
    CrossAsiDuplicateReference,
    DEDUPLICATION_METHOD_V1,
    IndexedCandidateDraft,
    deduplicate_asi_candidates,
)
from generator.models import (
    DEFAULT_GENERATION_LIMITS,
    GenerationLimits,
    StrictGeneratorModel,
    normalize_asi_code,
)
from generator.output_parser import (
    DEFAULT_MAX_JSON_DEPTH,
    DEFAULT_MAX_RAW_OUTPUT_BYTES,
    OutputParseError,
    parse_llm_generation_output,
)
from generator.providers.base import (
    GeneratorLLMProvider,
    ProviderErrorCategory,
    ProviderGenerationRequest,
    ProviderGenerationResponse,
    TokenUsage,
)
from generator.readiness import (
    AsiReadinessAssessment,
    ConfirmedContextSnapshot,
    ReadinessStatus,
    assess_target_readiness,
)
from generator.request_builder import (
    GenerationProvenanceInputs,
    GenerationRequestError,
    SupportedLanguage,
    build_sanitized_generation_request,
)
from generator.skills import GeneratorSkillError, GeneratorSkillLoader
from generator.validation import validate_parsed_output

_GENERATION_ID_RE = re.compile(r"^gen-[a-z0-9][a-z0-9_-]{5,47}$")

CandidateOrigin = Literal["ai_generated_original", "operator_edited", "imported_testcase"]
CandidateIdScope = Literal["ephemeral_generation_candidate"]

CandidateRejectionReasonCode = Literal[
    "unsupported_context_basis",
    "unverified_context_basis",
    "missing_provenance_context_basis",
    "missing_context_basis",
    "unconfirmed_reviewed_policy_basis",
    "duplicate_within_asi",
    "duplicate_across_asi",
    "exceeds_requested_count",
]

AsiGenerationStatus = Literal[
    "completed",
    "partial",
    "empty_with_context_gaps",
    "empty_all_rejected",
    "blocked",
    "provider_error",
    "truncated",
    "invalid_output",
]

OverallGenerationStatus = Literal[
    "completed",
    "partial",
    "empty_with_context_gaps",
    "blocked",
    "failed",
]

_RETRYABLE_PROVIDER_ERROR_CATEGORIES: frozenset[ProviderErrorCategory] = frozenset({
    ProviderErrorCategory.TIMEOUT,
    ProviderErrorCategory.NETWORK_ERROR,
    ProviderErrorCategory.RATE_LIMITED,
})

_SERVICE_LIMITATIONS: tuple[str, ...] = (
    "Deterministic backend checks validate JSON structure, ASI consistency, confirmed context_basis "
    "presence, and exact/normalized text deduplication; they do not prove semantic quality, "
    "semantic diversity, or absolute safety.",
    "GeneratorService never probes the Target, never invokes Judge/Evaluator logic, and never "
    "auto-persists or auto-executes generated candidates.",
    "Ephemeral candidate IDs are temporary generation identifiers distinct from final persisted "
    "Dataset/Testcase IDs assigned during explicit Save.",
)


class GenerationServiceError(ValueError):
    """Structured error raised when a generation request itself is invalid before execution."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_asi_string_mapping(raw: Any, *, field_name: str) -> dict[AsiCode, str]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"{field_name} must be a mapping from ASI code to string value.")
    normalized: dict[AsiCode, str] = {}
    for raw_key, raw_val in raw.items():
        if not isinstance(raw_key, str):
            raise ValueError(f"{field_name} keys must be strings.")
        code = normalize_asi_code(raw_key)
        if code in normalized:
            raise ValueError(f"Duplicate ASI key {code!r} in {field_name}.")
        if not isinstance(raw_val, str) or not raw_val.strip():
            raise ValueError(f"{field_name}[{code}] must be a non-empty string.")
        normalized[code] = raw_val.strip()
    return normalized


class GenerationServiceRequest(StrictGeneratorModel):
    """Validated input contract for GeneratorService.generate()."""

    target_id: str = Field(min_length=1, max_length=128)
    counts_by_asi: dict[AsiCode, int]
    language: SupportedLanguage = "en"
    focus_note: str | None = Field(default=None, max_length=1000)
    requested_scopes: dict[AsiCode, str] = Field(default_factory=dict)
    policy_ids_by_asi: dict[AsiCode, str] = Field(default_factory=dict)
    deduplicate_across_asi: bool = True
    # Default 1 provider call/ASI; explicit bounded retry allows at most 2 calls/ASI.
    max_calls_per_asi: int = Field(default=1, ge=1, le=2, strict=True)
    timeout_seconds: float | None = Field(default=None, gt=0.0, le=120.0, allow_inf_nan=False)
    extra_sensitive_values: tuple[str, ...] = ()

    @field_validator("target_id")
    @classmethod
    def check_target_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target_id must not be blank.")
        return cleaned

    @field_validator("counts_by_asi", mode="before")
    @classmethod
    def validate_counts(cls, value: Any) -> dict[AsiCode, int]:
        if not isinstance(value, Mapping):
            raise ValueError("counts_by_asi must be a mapping from ASI code to integer count.")
        return DEFAULT_GENERATION_LIMITS.validate_per_asi_counts(value)

    @field_validator("requested_scopes", mode="before")
    @classmethod
    def validate_requested_scopes(cls, value: Any) -> dict[AsiCode, str]:
        return _normalize_asi_string_mapping(value, field_name="requested_scopes")

    @field_validator("policy_ids_by_asi", mode="before")
    @classmethod
    def validate_policy_ids(cls, value: Any) -> dict[AsiCode, str]:
        return _normalize_asi_string_mapping(value, field_name="policy_ids_by_asi")

    @classmethod
    def from_selected_asi(
        cls,
        *,
        target_id: str,
        selected_asi: Sequence[str],
        default_count: int = DEFAULT_PER_ASI,
        count_overrides: Mapping[str, int] | None = None,
        language: SupportedLanguage = "en",
        focus_note: str | None = None,
        requested_scopes: Mapping[str, str] | None = None,
        policy_ids_by_asi: Mapping[str, str] | None = None,
        deduplicate_across_asi: bool = True,
        max_calls_per_asi: int = 1,
        timeout_seconds: float | None = None,
        extra_sensitive_values: tuple[str, ...] = (),
    ) -> "GenerationServiceRequest":
        """Build a request from a selected ASI list with default count and optional overrides."""
        if not selected_asi:
            raise ValueError("At least one ASI category must be selected.")
        if isinstance(default_count, bool) or not isinstance(default_count, int):
            raise ValueError("default_count must be an integer.")
        counts: dict[str, int] = {}
        for raw_asi in selected_asi:
            code = normalize_asi_code(raw_asi)
            if code in counts:
                raise ValueError(f"Duplicate ASI category {code!r} in selected_asi.")
            counts[code] = default_count
        if count_overrides:
            for raw_key, raw_count in count_overrides.items():
                code = normalize_asi_code(raw_key)
                if code not in counts:
                    raise ValueError(f"Override ASI {code!r} is not in selected_asi.")
                counts[code] = raw_count
        return cls(
            target_id=target_id,
            counts_by_asi=counts,
            language=language,
            focus_note=focus_note,
            requested_scopes=dict(requested_scopes or {}),
            policy_ids_by_asi=dict(policy_ids_by_asi or {}),
            deduplicate_across_asi=deduplicate_across_asi,
            max_calls_per_asi=max_calls_per_asi,
            timeout_seconds=timeout_seconds,
            extra_sensitive_values=extra_sensitive_values,
        )


class AcceptedCandidate(StrictGeneratorModel):
    """Backend-controlled, ephemeral accepted testcase candidate ready for G11.3C preview."""

    candidate_id: str = Field(min_length=8, max_length=96)
    candidate_id_scope: CandidateIdScope = "ephemeral_generation_candidate"
    origin: Literal["ai_generated_original"] = "ai_generated_original"
    operator_edited: Literal[False] = False
    generation_id: str = Field(min_length=8, max_length=64)
    asi_code: AsiCode
    asi_category: AsiCategory
    effective_scope: str = Field(min_length=1, max_length=128)
    source_index: int = Field(ge=0, strict=True)
    prompt: str = Field(min_length=1)
    description: str = Field(min_length=1, max_length=512)
    strategy_tag: str = Field(min_length=2, max_length=64)
    context_basis: tuple[str, ...] = Field(min_length=1)
    scope_note: str = Field(min_length=1, max_length=512)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RejectedCandidateRecord(StrictGeneratorModel):
    """Structured rejection metadata for a candidate dropped during validation or deduplication."""

    source_index: int = Field(ge=0, strict=True)
    asi_code: AsiCode
    reason_code: CandidateRejectionReasonCode
    reason_message: str = Field(min_length=1, max_length=512)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    duplicate_of_asi_code: AsiCode | None = None
    duplicate_of_source_index: int | None = Field(default=None, ge=0, strict=True)
    duplicate_of_candidate_id: str | None = None
    invalid_context_fields: tuple[str, ...] = ()


class ChunkExecutionSummary(StrictGeneratorModel):
    """Secret-free per-chunk execution accounting for bounded multi-chunk generation."""

    chunk_index: int = Field(ge=1, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    requested_count: int = Field(ge=1, le=DEFAULT_GENERATION_CHUNK_SIZE, strict=True)
    generated_count: int = Field(default=0, ge=0, strict=True)
    accepted_count: int = Field(default=0, ge=0, strict=True)
    rejected_count: int = Field(default=0, ge=0, strict=True)
    status: AsiGenerationStatus
    dispatched: bool = False
    blocked_before_dispatch: bool = False
    finish_reason: str | None = None
    call_count: int = Field(default=0, ge=0, le=2, strict=True)
    duration_ms: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    token_usage: TokenUsage | None = None
    sanitized_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: str | None = None
    provider_error_category: ProviderErrorCategory | None = None


def plan_asi_chunks(requested_count: int) -> tuple[int, ...]:
    """Deterministically split a per-ASI testcase count into fixed-size chunks (size 15, max 4)."""
    if isinstance(requested_count, bool) or not isinstance(requested_count, int):
        raise ValueError("requested_count must be an integer.")
    if requested_count < 1 or requested_count > HARD_MAX_PER_ASI:
        raise ValueError(
            f"requested_count ({requested_count}) must be between 1 and {HARD_MAX_PER_ASI}."
        )
    if requested_count <= DEFAULT_GENERATION_CHUNK_SIZE:
        return (requested_count,)
    full_chunks, remainder = divmod(requested_count, DEFAULT_GENERATION_CHUNK_SIZE)
    plan = [DEFAULT_GENERATION_CHUNK_SIZE] * full_chunks
    if remainder > 0:
        plan.append(remainder)
    if len(plan) > MAX_PLANNED_CHUNKS_PER_ASI:
        raise ValueError(
            f"Planned chunk count ({len(plan)}) exceeds hard limit {MAX_PLANNED_CHUNKS_PER_ASI}."
        )
    return tuple(plan)


class AsiGenerationResult(StrictGeneratorModel):
    """Complete per-ASI outcome, statistics, provenance, and accepted/rejected candidates."""

    asi_code: AsiCode
    asi_category: AsiCategory
    status: AsiGenerationStatus
    effective_scope: str | None = None
    readiness_status: ReadinessStatus
    readiness_blockers: tuple[str, ...] = ()
    readiness_warnings: tuple[str, ...] = ()
    requested_count: int = Field(ge=1, strict=True)
    generated_count: int = Field(default=0, ge=0, strict=True)
    pre_dedup_valid_count: int = Field(default=0, ge=0, strict=True)
    post_dedup_valid_count: int = Field(default=0, ge=0, strict=True)
    accepted_count: int = Field(default=0, ge=0, strict=True)
    rejected_count: int = Field(default=0, ge=0, strict=True)
    duplicate_rejected_count: int = Field(default=0, ge=0, strict=True)
    accepted_candidates: tuple[AcceptedCandidate, ...] = ()
    rejected_candidates: tuple[RejectedCandidateRecord, ...] = ()
    rejection_reason_counts: dict[str, int] = Field(default_factory=dict)
    context_gaps: tuple[str, ...] = ()
    error_code: str | None = None
    error_message: str | None = Field(default=None, max_length=512)
    provider_error_category: ProviderErrorCategory | None = None
    finish_reason: str | None = None
    provider_id: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    skill_id: str | None = None
    skill_version: str | None = None
    skill_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sanitized_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reviewed_policy_id: str | None = None
    reviewed_policy_revision_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    call_count: int = Field(default=0, ge=0, le=MAX_TOTAL_PROVIDER_CALLS_PER_ASI, strict=True)
    duration_ms: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    token_usage: TokenUsage | None = None
    provenance_inputs: GenerationProvenanceInputs | None = None
    chunking_used: bool = False
    planned_chunk_count: int = Field(default=1, ge=1, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    attempted_chunk_count: int = Field(default=0, ge=0, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    executed_chunk_count: int = Field(default=0, ge=0, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    completed_chunk_count: int = Field(default=0, ge=0, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    budget_blocked_chunk_count: int = Field(default=0, ge=0, le=MAX_PLANNED_CHUNKS_PER_ASI, strict=True)
    dispatched_request_sha256s: tuple[str, ...] = ()
    chunk_summaries: tuple[ChunkExecutionSummary, ...] = ()


class GenerationResult(StrictGeneratorModel):
    """Top-level immutable output returned by GeneratorService.generate()."""

    generation_id: str = Field(min_length=8, max_length=64)
    created_at: str = Field(min_length=10, max_length=64)
    target_id: str = Field(min_length=1, max_length=128)
    target_revision_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    application_context_revision_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    context_snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    language: SupportedLanguage
    provider_id: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=128)
    deduplication_method: Literal["exact_normalized_text_v1"] = DEDUPLICATION_METHOD_V1
    deduplicate_across_asi: bool
    max_calls_per_asi: int = Field(ge=1, le=2, strict=True)
    overall_status: OverallGenerationStatus
    meets_requested_counts: bool
    has_accepted_candidates: bool
    total_requested: int = Field(ge=1, strict=True)
    total_generated: int = Field(ge=0, strict=True)
    total_accepted: int = Field(ge=0, strict=True)
    total_rejected: int = Field(ge=0, strict=True)
    total_call_count: int = Field(ge=0, strict=True)
    total_duration_ms: float = Field(ge=0.0, allow_inf_nan=False)
    total_token_usage: TokenUsage | None = None
    authorized_output_token_budget: int = Field(
        default=MAX_GENERATION_OUTPUT_TOKEN_BUDGET, ge=1, strict=True
    )
    allocated_output_tokens: int = Field(default=0, ge=0, strict=True)
    token_usage_unreported_calls: int = Field(default=0, ge=0, strict=True)
    asi_order: tuple[AsiCode, ...]
    asi_results: dict[AsiCode, AsiGenerationResult]
    explicit_policy_ids_by_asi: dict[AsiCode, str] = Field(default_factory=dict)
    accepted_candidates: tuple[AcceptedCandidate, ...] = ()
    rejection_reason_counts: dict[str, int] = Field(default_factory=dict)
    limitations: tuple[str, ...] = _SERVICE_LIMITATIONS
    auto_persisted: Literal[False] = False
    auto_executed: Literal[False] = False


def _sum_token_usages(usages: Sequence[TokenUsage | None]) -> TokenUsage | None:
    present = [u for u in usages if u is not None]
    if not present:
        return None
    prompt_vals = [u.prompt_tokens for u in present if u.prompt_tokens is not None]
    comp_vals = [u.completion_tokens for u in present if u.completion_tokens is not None]
    total_vals = [u.total_tokens for u in present if u.total_tokens is not None]
    if not prompt_vals and not comp_vals and not total_vals:
        return None
    return TokenUsage(
        prompt_tokens=sum(prompt_vals) if prompt_vals else None,
        completion_tokens=sum(comp_vals) if comp_vals else None,
        total_tokens=sum(total_vals) if total_vals else None,
    )


def _is_retryable_provider_response(response: ProviderGenerationResponse) -> bool:
    """Strictly allow at most one bounded retry for transient transport/rate errors only."""
    if response.ok or response.call_count == 0 or response.error_category is None:
        return False
    if response.error_category in _RETRYABLE_PROVIDER_ERROR_CATEGORIES:
        return True
    if (
        response.error_category == ProviderErrorCategory.HTTP_ERROR
        and response.http_status is not None
        and response.http_status >= 500
    ):
        return True
    return False


def _count_reasons(records: Sequence[RejectedCandidateRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in records:
        counts[rec.reason_code] = counts.get(rec.reason_code, 0) + 1
    return dict(sorted(counts.items()))


def _compute_overall_status(
    asi_results: Mapping[AsiCode, AsiGenerationResult],
) -> OverallGenerationStatus:
    statuses = [res.status for res in asi_results.values()]
    total_accepted = sum(res.accepted_count for res in asi_results.values())
    if statuses and all(st == "completed" for st in statuses):
        return "completed"
    if statuses and all(st == "blocked" for st in statuses):
        return "blocked"
    if total_accepted > 0:
        return "partial"
    if any(st == "empty_with_context_gaps" for st in statuses) and all(
        st in {"empty_with_context_gaps", "blocked"} for st in statuses
    ):
        return "empty_with_context_gaps"
    return "failed"


def _raise_if_cancelled(cancel_event: Event | None, reason: str) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise RunCancelledError(reason)


class _GenerationBudgetTracker:
    """Per-generation call & output-token budget guard (never shared across requests)."""

    def __init__(
        self,
        *,
        max_total_calls: int = MAX_GENERATION_TOTAL_PROVIDER_CALLS,
        output_token_budget: int = MAX_GENERATION_OUTPUT_TOKEN_BUDGET,
    ) -> None:
        self.max_total_calls = max_total_calls
        self.output_token_budget = output_token_budget
        self.calls_used: int = 0
        self.allocated_output_tokens: int = 0
        self.reported_completion_tokens: int = 0
        self.reported_usage_present: bool = False
        self.unreported_usage_calls: int = 0

    def check_dispatch(self, next_max_tokens: int, *, asi_calls_used: int) -> tuple[str, str] | None:
        if asi_calls_used >= MAX_TOTAL_PROVIDER_CALLS_PER_ASI:
            return (
                "asi_call_budget_exceeded",
                f"Per-ASI provider call budget ({MAX_TOTAL_PROVIDER_CALLS_PER_ASI}) reached.",
            )
        if self.calls_used >= self.max_total_calls:
            return (
                "generation_call_budget_exceeded",
                f"Generation-wide provider call budget ({self.max_total_calls}) reached.",
            )
        if self.allocated_output_tokens + next_max_tokens > self.output_token_budget:
            return (
                "generation_output_token_budget_exceeded",
                f"Authorized generation output token budget ({self.output_token_budget}) would be exceeded.",
            )
        if self.reported_usage_present and self.reported_completion_tokens >= self.output_token_budget:
            return (
                "generation_reported_token_budget_exceeded",
                f"Provider-reported completion tokens reached generation ceiling ({self.output_token_budget}).",
            )
        return None

    def record_attempt(self, max_tokens: int, response: ProviderGenerationResponse) -> None:
        if response.call_count <= 0:
            return
        self.calls_used += response.call_count
        self.allocated_output_tokens += max_tokens
        if response.token_usage is not None and response.token_usage.completion_tokens is not None:
            self.reported_usage_present = True
            self.reported_completion_tokens += response.token_usage.completion_tokens
        else:
            self.unreported_usage_calls += response.call_count


class GeneratorService:
    """Stateless Context-aware Generator Service (G11.3B + Phase 2 bounded chunking).

    Holds no global state, never writes to AppData or DatasetRepository, never
    contacts a Target, and never invokes Judge/Evaluator components.
    """

    def __init__(
        self,
        *,
        catalog: Any,
        application_contexts: Any | None,
        provider: GeneratorLLMProvider,
        skill_loader: GeneratorSkillLoader | None = None,
        policy_store: Any | None = None,
        limits: GenerationLimits = DEFAULT_GENERATION_LIMITS,
        max_raw_output_bytes: int = DEFAULT_MAX_RAW_OUTPUT_BYTES,
        max_json_depth: int = DEFAULT_MAX_JSON_DEPTH,
    ) -> None:
        self._catalog = catalog
        self._application_contexts = application_contexts
        self._provider = provider
        self._skill_loader = skill_loader if skill_loader is not None else GeneratorSkillLoader()
        self._policy_store = policy_store
        self._limits = limits
        self._max_raw_output_bytes = max_raw_output_bytes
        self._max_json_depth = max_json_depth

    def _invoke_provider_chunk(
        self,
        provider_request: ProviderGenerationRequest,
        *,
        asi_calls_used: int,
        asi_retries_remaining: int,
        budget: _GenerationBudgetTracker,
        cancel_event: Event | None = None,
    ) -> tuple[ProviderGenerationResponse | None, int, float, TokenUsage | None, int, tuple[str, str] | None]:
        """Execute 1 call for one chunk plus at most 1 ASI-wide transient retry (zero nested retries)."""
        chunk_calls = 0
        chunk_duration_ms = 0.0
        usages: list[TokenUsage | None] = []
        retries_consumed = 0
        last_response: ProviderGenerationResponse | None = None

        max_attempts_this_chunk = 2 if asi_retries_remaining > 0 else 1
        for attempt in range(max_attempts_this_chunk):
            _raise_if_cancelled(cancel_event, "generator_cancelled_before_provider_call")
            budget_err = budget.check_dispatch(
                provider_request.max_tokens,
                asi_calls_used=asi_calls_used + chunk_calls,
            )
            if budget_err is not None:
                if last_response is not None:
                    # First attempt failed transiently, but budget forbids retry: return last response honestly.
                    break
                return None, 0, 0.0, None, 0, budget_err

            response = self._provider.generate(provider_request)
            last_response = response
            chunk_calls += response.call_count
            chunk_duration_ms += response.duration_ms
            usages.append(response.token_usage)
            budget.record_attempt(provider_request.max_tokens, response)
            if attempt > 0:
                retries_consumed += 1

            _raise_if_cancelled(cancel_event, "generator_cancelled_after_provider_call")

            if attempt + 1 >= max_attempts_this_chunk or not _is_retryable_provider_response(response):
                break

        return last_response, chunk_calls, chunk_duration_ms, _sum_token_usages(usages), retries_consumed, None

    def _invoke_provider_bounded(
        self,
        provider_request: ProviderGenerationRequest,
        *,
        max_calls: int,
    ) -> tuple[ProviderGenerationResponse, int, float, TokenUsage | None]:
        """Backward-compatible single-request helper (1 call default, max 2 with transient retry)."""
        budget = _GenerationBudgetTracker()
        resp, calls, duration_ms, usage, _, _ = self._invoke_provider_chunk(
            provider_request,
            asi_calls_used=0,
            asi_retries_remaining=max(0, min(max_calls, 2) - 1),
            budget=budget,
            cancel_event=None,
        )
        assert resp is not None
        return resp, calls, duration_ms, usage

    def _generate_single_asi(
        self,
        *,
        generation_id: str,
        asi_code: AsiCode,
        requested_count: int,
        snapshot: ConfirmedContextSnapshot | None,
        assessment: AsiReadinessAssessment,
        request: GenerationServiceRequest,
        token_ceiling: int,
        cross_asi_seen: dict[str, CrossAsiDuplicateReference],
        budget: _GenerationBudgetTracker | None = None,
        cancel_event: Event | None = None,
    ) -> AsiGenerationResult:
        _raise_if_cancelled(cancel_event, f"generator_cancelled_before_{asi_code.lower()}")
        active_budget = budget if budget is not None else _GenerationBudgetTracker()
        chunk_plan = plan_asi_chunks(requested_count)
        planned_chunk_count = len(chunk_plan)
        chunking_used = planned_chunk_count > 1

        category = ASI_CODE_TO_CATEGORY[asi_code]
        provider_id = self._provider.provider_id
        model_name = self._provider.model_name

        # 1. Blocked readiness: zero skill load, zero provider call, never downgrade scope.
        if snapshot is None or assessment.status == "blocked":
            return AsiGenerationResult(
                asi_code=asi_code,
                asi_category=category,
                status="blocked",
                effective_scope=assessment.effective_scope,
                readiness_status=assessment.status,
                readiness_blockers=assessment.blockers,
                readiness_warnings=assessment.warnings,
                requested_count=requested_count,
                error_code="readiness_blocked",
                error_message=(
                    "Generation blocked by deterministic readiness: "
                    + ", ".join(assessment.blockers)
                    + "."
                    if assessment.blockers
                    else "Generation blocked by deterministic readiness."
                ),
                provider_id=provider_id,
                model=model_name,
                reviewed_policy_id=assessment.reviewed_policy_id,
                reviewed_policy_revision_sha256=assessment.reviewed_policy_revision_sha256,
                chunking_used=chunking_used,
                planned_chunk_count=planned_chunk_count,
                executed_chunk_count=0,
                completed_chunk_count=0,
            )

        # 2. Load allowlisted Generation Skill bundle once per ASI.
        try:
            skill_bundle = self._skill_loader.load(asi_code)
        except GeneratorSkillError as exc:
            return AsiGenerationResult(
                asi_code=asi_code,
                asi_category=category,
                status="blocked",
                effective_scope=assessment.effective_scope,
                readiness_status=assessment.status,
                readiness_blockers=assessment.blockers,
                readiness_warnings=assessment.warnings,
                requested_count=requested_count,
                error_code=f"skill_error:{exc.code}",
                error_message=exc.message[:512],
                provider_id=provider_id,
                model=model_name,
                reviewed_policy_id=assessment.reviewed_policy_id,
                reviewed_policy_revision_sha256=assessment.reviewed_policy_revision_sha256,
                chunking_used=chunking_used,
                planned_chunk_count=planned_chunk_count,
                executed_chunk_count=0,
                completed_chunk_count=0,
            )

        # 3. Execute bounded sequential chunks with shared cross-chunk dedup & ASI-wide retry cap.
        asi_retries_remaining = max(0, request.max_calls_per_asi - 1)
        asi_calls_used = 0
        total_duration_ms = 0.0
        total_generated = 0
        total_pre_dedup = 0
        total_post_dedup = 0
        total_dup_rejected = 0
        completed_chunk_count = 0
        budget_blocked_chunk_count = 0
        next_source_index = 0

        asi_within_seen: dict[str, IndexedCandidateDraft] = {}
        source_index_to_candidate_id: dict[int, str] = {}
        accepted: list[AcceptedCandidate] = []
        rejected: list[RejectedCandidateRecord] = []
        prior_strategy_tags: set[str] = set()
        all_context_gaps: list[str] = []
        chunk_summaries: list[ChunkExecutionSummary] = []
        dispatched_request_hashes: list[str] = []
        chunk_token_usages: list[TokenUsage | None] = []

        first_prov: GenerationProvenanceInputs | None = None
        first_dispatched_prov: GenerationProvenanceInputs | None = None
        last_finish_reason: str | None = None
        last_provider_id = provider_id
        last_model = model_name
        failure_status: AsiGenerationStatus | None = None
        failure_code: str | None = None
        failure_message: str | None = None
        failure_category: ProviderErrorCategory | None = None

        for chunk_idx, chunk_requested in enumerate(chunk_plan, start=1):
            _raise_if_cancelled(cancel_event, f"generator_cancelled_before_chunk_{chunk_idx}")

            req_id = (
                f"{generation_id}-{asi_code.lower()}-c{chunk_idx}"
                if chunking_used
                else f"{generation_id}-{asi_code.lower()}"
            )
            try:
                envelope = build_sanitized_generation_request(
                    skill_bundle=skill_bundle,
                    snapshot=snapshot,
                    assessment=assessment,
                    requested_count=chunk_requested,
                    language=request.language,
                    focus_note=request.focus_note,
                    token_ceiling=token_ceiling,
                    limits=self._limits,
                    request_id=req_id,
                    extra_sensitive_values=request.extra_sensitive_values,
                    chunk_index=chunk_idx if chunking_used else None,
                    total_chunks=planned_chunk_count if chunking_used else None,
                    prior_strategy_tags=sorted(prior_strategy_tags) if chunking_used and prior_strategy_tags else None,
                )
            except GenerationRequestError as exc:
                if not chunk_summaries:
                    return AsiGenerationResult(
                        asi_code=asi_code,
                        asi_category=category,
                        status="blocked",
                        effective_scope=assessment.effective_scope,
                        readiness_status=assessment.status,
                        readiness_blockers=assessment.blockers,
                        readiness_warnings=assessment.warnings,
                        requested_count=requested_count,
                        error_code=f"request_error:{exc.code}",
                        error_message=exc.message[:512],
                        provider_id=provider_id,
                        model=model_name,
                        skill_id=skill_bundle.identity.id,
                        skill_version=skill_bundle.identity.version,
                        skill_sha256=skill_bundle.identity.sha256,
                        reviewed_policy_id=assessment.reviewed_policy_id,
                        reviewed_policy_revision_sha256=assessment.reviewed_policy_revision_sha256,
                        chunking_used=chunking_used,
                        planned_chunk_count=planned_chunk_count,
                        attempted_chunk_count=0,
                        executed_chunk_count=0,
                        completed_chunk_count=0,
                        budget_blocked_chunk_count=0,
                    )
                failure_status = "blocked"
                failure_code = f"request_error:{exc.code}"
                failure_message = exc.message[:512]
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        status="blocked",
                        dispatched=False,
                        blocked_before_dispatch=True,
                        error_code=failure_code,
                    )
                )
                break

            provider_req = envelope.provider_request
            if request.timeout_seconds is not None:
                provider_req = provider_req.model_copy(update={"timeout_seconds": request.timeout_seconds})

            prov = envelope.provenance_inputs
            if first_prov is None:
                first_prov = prov

            response, chunk_calls, chunk_duration_ms, chunk_usage, retries_used, budget_err = (
                self._invoke_provider_chunk(
                    provider_req,
                    asi_calls_used=asi_calls_used,
                    asi_retries_remaining=asi_retries_remaining,
                    budget=active_budget,
                    cancel_event=cancel_event,
                )
            )
            asi_calls_used += chunk_calls
            asi_retries_remaining = max(0, asi_retries_remaining - retries_used)
            total_duration_ms += chunk_duration_ms
            chunk_token_usages.append(chunk_usage)

            chunk_dispatched = chunk_calls > 0
            if chunk_dispatched:
                if first_dispatched_prov is None:
                    first_dispatched_prov = prov
                dispatched_request_hashes.append(prov.request_sha256)

            if budget_err is not None or response is None:
                err_code, err_msg = budget_err or (
                    "generation_budget_exceeded",
                    "Generation call or token budget exceeded.",
                )
                budget_blocked_chunk_count += 1
                failure_status = "provider_error"
                failure_code = err_code
                failure_message = err_msg[:512]
                failure_category = ProviderErrorCategory.CONFIGURATION_ERROR
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        status="provider_error",
                        dispatched=False,
                        blocked_before_dispatch=True,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                        error_code=err_code,
                        provider_error_category=failure_category,
                    )
                )
                break

            last_finish_reason = response.finish_reason
            last_provider_id = response.provider_id
            last_model = response.model

            # Classify truncated / provider error outcomes before JSON parsing.
            if (
                response.error_category == ProviderErrorCategory.TRUNCATED_RESPONSE
                or (isinstance(response.finish_reason, str) and response.finish_reason.strip().lower() == "length")
            ):
                err_cat = response.error_category or ProviderErrorCategory.TRUNCATED_RESPONSE
                failure_status = "truncated"
                failure_code = "truncated_output"
                failure_message = (
                    response.error_message
                    or "LLM generation output was truncated before completion (finish_reason=length)."
                )[:512]
                failure_category = err_cat
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        status="truncated",
                        dispatched=chunk_dispatched,
                        blocked_before_dispatch=not chunk_dispatched,
                        finish_reason=response.finish_reason,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                        error_code=failure_code,
                        provider_error_category=err_cat,
                    )
                )
                break

            if not response.ok:
                err_cat = response.error_category or ProviderErrorCategory.HTTP_ERROR
                failure_status = "provider_error"
                failure_code = f"provider_error:{err_cat.value}"
                failure_message = (response.error_message or "Generator provider call failed.")[:512]
                failure_category = err_cat
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        status="provider_error",
                        dispatched=chunk_dispatched,
                        blocked_before_dispatch=not chunk_dispatched,
                        finish_reason=response.finish_reason,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                        error_code=failure_code,
                        provider_error_category=err_cat,
                    )
                )
                break

            # Strictly parse untrusted raw_text into RawGenerationOutputContract.
            try:
                parsed = parse_llm_generation_output(
                    response.raw_text,
                    finish_reason=response.finish_reason,
                    max_raw_bytes=self._max_raw_output_bytes,
                    max_depth=self._max_json_depth,
                )
            except OutputParseError as exc:
                parse_status: AsiGenerationStatus = (
                    "truncated" if exc.code == "truncated_output" else "invalid_output"
                )
                failure_status = parse_status
                failure_code = exc.code
                failure_message = exc.message[:512]
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        status=parse_status,
                        dispatched=chunk_dispatched,
                        blocked_before_dispatch=not chunk_dispatched,
                        finish_reason=response.finish_reason,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                        error_code=exc.code,
                    )
                )
                break

            contract = parsed.contract
            chunk_generated = len(contract.candidates)
            total_generated += chunk_generated
            for gap in contract.context_gaps:
                if gap not in all_context_gaps:
                    all_context_gaps.append(gap)

            # Deterministic backend candidate validation (ASI consistency + confirmed context_basis).
            val_outcome = validate_parsed_output(
                contract,
                expected_asi_code=asi_code,
                snapshot=snapshot,
                assessment=assessment,
                provenance_inputs=prov,
                source_index_offset=next_source_index,
            )
            if not val_outcome.asi_matched:
                failure_status = "invalid_output"
                failure_code = "asi_mismatch"
                failure_message = (
                    val_outcome.asi_mismatch_message
                    or f"LLM output ASI category does not match requested {asi_code}."
                )[:512]
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        generated_count=chunk_generated,
                        status="invalid_output",
                        dispatched=chunk_dispatched,
                        blocked_before_dispatch=not chunk_dispatched,
                        finish_reason=response.finish_reason,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                        error_code=failure_code,
                    )
                )
                break

            next_source_index += chunk_generated

            # Explicit empty candidates with valid context_gaps (NEVER treated as completed!).
            if chunk_generated == 0:
                completed_chunk_count += 1
                chunk_summaries.append(
                    ChunkExecutionSummary(
                        chunk_index=chunk_idx,
                        requested_count=chunk_requested,
                        generated_count=0,
                        accepted_count=0,
                        rejected_count=0,
                        status="empty_with_context_gaps",
                        dispatched=chunk_dispatched,
                        blocked_before_dispatch=not chunk_dispatched,
                        finish_reason=response.finish_reason,
                        call_count=chunk_calls,
                        duration_ms=chunk_duration_ms,
                        token_usage=chunk_usage,
                        sanitized_request_sha256=prov.request_sha256,
                    )
                )
                # Model reported explicit context gaps; do not waste remaining chunks with identical context.
                break

            # Deterministic exact/normalized deduplication across all chunks of this ASI + cross-ASI.
            chunk_within_seen = dict(asi_within_seen)
            dedup_outcome = deduplicate_asi_candidates(
                val_outcome.valid_candidates,
                asi_code=asi_code,
                within_seen=chunk_within_seen,
                cross_asi_seen=cross_asi_seen,
                deduplicate_across_asi=request.deduplicate_across_asi,
            )
            total_pre_dedup += dedup_outcome.pre_dedup_count
            total_post_dedup += dedup_outcome.post_dedup_count
            total_dup_rejected += (
                dedup_outcome.within_asi_duplicates_removed
                + dedup_outcome.across_asi_duplicates_removed
            )

            # Cap chunk accepted candidates at chunk_requested (and <= remaining ASI need) without silent truncation.
            remaining_asi_capacity = max(0, requested_count - len(accepted))
            chunk_limit = min(chunk_requested, remaining_asi_capacity)
            kept_within_limit = dedup_outcome.kept[:chunk_limit]
            excess_over_requested = dedup_outcome.kept[chunk_limit:]

            chunk_accepted_count = 0
            for item in kept_within_limit:
                seq = len(accepted) + 1
                candidate_id = f"{generation_id}:{asi_code.lower()}:{seq:03d}"
                source_index_to_candidate_id[item.source_index] = candidate_id
                asi_within_seen[item.normalized_prompt_sha256] = item
                prior_strategy_tags.add(item.draft.strategy_tag)
                accepted.append(
                    AcceptedCandidate(
                        candidate_id=candidate_id,
                        generation_id=generation_id,
                        asi_code=asi_code,
                        asi_category=category,
                        effective_scope=prov.effective_scope,
                        source_index=item.source_index,
                        prompt=item.draft.prompt,
                        description=item.draft.description,
                        strategy_tag=item.draft.strategy_tag,
                        context_basis=item.draft.context_basis,
                        scope_note=item.draft.scope_note,
                        prompt_sha256=item.prompt_sha256,
                        normalized_prompt_sha256=item.normalized_prompt_sha256,
                    )
                )
                chunk_accepted_count += 1
                if item.normalized_prompt_sha256 not in cross_asi_seen:
                    cross_asi_seen[item.normalized_prompt_sha256] = CrossAsiDuplicateReference(
                        asi_code=asi_code,
                        source_index=item.source_index,
                        candidate_id=candidate_id,
                    )

            chunk_rejected_count = 0
            for rej in val_outcome.rejected_candidates:
                rejected.append(
                    RejectedCandidateRecord(
                        source_index=rej.source_index,
                        asi_code=asi_code,
                        reason_code=rej.reason_code,
                        reason_message=rej.reason_message,
                        prompt_sha256=rej.prompt_sha256,
                        normalized_prompt_sha256=rej.normalized_prompt_sha256,
                        invalid_context_fields=rej.invalid_context_fields,
                    )
                )
                chunk_rejected_count += 1

            for dup in dedup_outcome.rejected:
                ref_candidate_id = dup.duplicate_of_candidate_id
                reason_msg = dup.reason_message
                if ref_candidate_id is None and dup.duplicate_of_asi_code == asi_code:
                    ref_candidate_id = source_index_to_candidate_id.get(dup.duplicate_of_source_index)
                    if ref_candidate_id is None:
                        reason_msg = (
                            f"{dup.reason_message} Referenced raw candidate at source index "
                            f"{dup.duplicate_of_source_index} was not accepted (exceeds_requested_count); "
                            "duplicate_of_candidate_id is null."
                        )[:512]
                rejected.append(
                    RejectedCandidateRecord(
                        source_index=dup.source_index,
                        asi_code=asi_code,
                        reason_code=dup.reason_code,
                        reason_message=reason_msg,
                        prompt_sha256=dup.prompt_sha256,
                        normalized_prompt_sha256=dup.normalized_prompt_sha256,
                        duplicate_of_asi_code=dup.duplicate_of_asi_code,
                        duplicate_of_source_index=dup.duplicate_of_source_index,
                        duplicate_of_candidate_id=ref_candidate_id,
                    )
                )
                chunk_rejected_count += 1

            for extra_item in excess_over_requested:
                if chunking_used:
                    excess_msg = (
                        f"Candidate exceeds chunk requested_count ({chunk_requested}) in chunk "
                        f"{chunk_idx}/{planned_chunk_count} for {asi_code} "
                        f"(total requested {requested_count}); explicitly rejected instead of silently truncating."
                    )
                else:
                    excess_msg = (
                        f"Candidate exceeds requested_count ({requested_count}) for {asi_code}; "
                        "explicitly rejected instead of silently truncating."
                    )
                rejected.append(
                    RejectedCandidateRecord(
                        source_index=extra_item.source_index,
                        asi_code=asi_code,
                        reason_code="exceeds_requested_count",
                        reason_message=excess_msg,
                        prompt_sha256=extra_item.prompt_sha256,
                        normalized_prompt_sha256=extra_item.normalized_prompt_sha256,
                    )
                )
                chunk_rejected_count += 1

            if chunk_accepted_count == chunk_requested:
                chunk_status: AsiGenerationStatus = "completed"
            elif chunk_accepted_count > 0:
                chunk_status = "partial"
            else:
                chunk_status = "empty_all_rejected"

            completed_chunk_count += 1
            chunk_summaries.append(
                ChunkExecutionSummary(
                    chunk_index=chunk_idx,
                    requested_count=chunk_requested,
                    generated_count=chunk_generated,
                    accepted_count=chunk_accepted_count,
                    rejected_count=chunk_rejected_count,
                    status=chunk_status,
                    dispatched=chunk_dispatched,
                    blocked_before_dispatch=not chunk_dispatched,
                    finish_reason=response.finish_reason,
                    call_count=chunk_calls,
                    duration_ms=chunk_duration_ms,
                    token_usage=chunk_usage,
                    sanitized_request_sha256=prov.request_sha256,
                )
            )

        rejected.sort(key=lambda r: r.source_index)
        accepted_count = len(accepted)
        rejected_count = len(rejected)
        dispatched_chunk_count = sum(1 for cs in chunk_summaries if cs.dispatched)

        # Composite sanitized_request_sha256 strictly reflects requests actually dispatched to the provider.
        if not dispatched_request_hashes:
            asi_request_sha256: str | None = None
        elif not chunking_used:
            asi_request_sha256 = dispatched_request_hashes[0]
        else:
            asi_request_sha256 = sha256("|".join(dispatched_request_hashes).encode("utf-8")).hexdigest()

        asi_provenance: GenerationProvenanceInputs | None = None
        if first_dispatched_prov is not None and asi_request_sha256 is not None:
            if chunking_used:
                asi_provenance = first_dispatched_prov.model_copy(
                    update={"requested_count": requested_count, "request_sha256": asi_request_sha256}
                )
            else:
                asi_provenance = first_dispatched_prov

        if accepted_count == requested_count:
            asi_status: AsiGenerationStatus = "completed"
        elif accepted_count > 0:
            asi_status = "partial"
        elif failure_status is not None:
            asi_status = failure_status
        elif total_generated == 0 and all_context_gaps:
            asi_status = "empty_with_context_gaps"
        else:
            asi_status = "empty_all_rejected"

        return AsiGenerationResult(
            asi_code=asi_code,
            asi_category=category,
            status=asi_status,
            effective_scope=first_prov.effective_scope if first_prov is not None else assessment.effective_scope,
            readiness_status=assessment.status,
            readiness_blockers=assessment.blockers,
            readiness_warnings=assessment.warnings,
            requested_count=requested_count,
            generated_count=total_generated,
            pre_dedup_valid_count=total_pre_dedup,
            post_dedup_valid_count=total_post_dedup,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            duplicate_rejected_count=total_dup_rejected,
            accepted_candidates=tuple(accepted),
            rejected_candidates=tuple(rejected),
            rejection_reason_counts=_count_reasons(rejected),
            context_gaps=tuple(all_context_gaps),
            error_code=failure_code,
            error_message=failure_message,
            provider_error_category=failure_category,
            finish_reason=last_finish_reason,
            provider_id=last_provider_id,
            model=last_model,
            skill_id=first_prov.skill_id if first_prov is not None else skill_bundle.identity.id,
            skill_version=first_prov.skill_version if first_prov is not None else skill_bundle.identity.version,
            skill_sha256=first_prov.skill_sha256 if first_prov is not None else skill_bundle.identity.sha256,
            sanitized_request_sha256=asi_request_sha256,
            reviewed_policy_id=(
                first_prov.reviewed_policy_id if first_prov is not None else assessment.reviewed_policy_id
            ),
            reviewed_policy_revision_sha256=(
                first_prov.reviewed_policy_revision_sha256
                if first_prov is not None
                else assessment.reviewed_policy_revision_sha256
            ),
            call_count=asi_calls_used,
            duration_ms=total_duration_ms,
            token_usage=_sum_token_usages(chunk_token_usages),
            provenance_inputs=asi_provenance,
            chunking_used=chunking_used,
            planned_chunk_count=planned_chunk_count,
            attempted_chunk_count=len(chunk_summaries),
            executed_chunk_count=dispatched_chunk_count,
            completed_chunk_count=completed_chunk_count,
            budget_blocked_chunk_count=budget_blocked_chunk_count,
            dispatched_request_sha256s=tuple(dispatched_request_hashes),
            chunk_summaries=tuple(chunk_summaries),
        )

    def generate(
        self,
        request: GenerationServiceRequest,
        *,
        generation_id: str | None = None,
        cancel_event: Event | None = None,
    ) -> GenerationResult:
        """Execute bounded Context-aware Generation across requested ASI categories."""
        if not isinstance(request, GenerationServiceRequest):
            raise GenerationServiceError(
                "invalid_request_type",
                "request must be a GenerationServiceRequest instance.",
            )

        # Enforce service-specific GenerationLimits (which may be tighter than defaults).
        try:
            validated_counts = self._limits.validate_per_asi_counts(request.counts_by_asi)
        except ValueError as exc:
            raise GenerationServiceError("invalid_generation_limits", str(exc)) from exc

        if generation_id is not None:
            cleaned_gen_id = generation_id.strip()
            if not _GENERATION_ID_RE.fullmatch(cleaned_gen_id):
                raise GenerationServiceError(
                    "invalid_generation_id",
                    "generation_id must match pattern ^gen-[a-z0-9][a-z0-9_-]{5,47}$.",
                )
            resolved_gen_id = cleaned_gen_id
        else:
            resolved_gen_id = f"gen-{uuid4().hex[:16]}"

        _raise_if_cancelled(cancel_event, "generator_cancelled_before_start")

        # Canonical deterministic ASI processing order independent of caller dict insertion order.
        asi_order: tuple[AsiCode, ...] = tuple(
            code for code in SUPPORTED_ASI_CODES if code in validated_counts
        )

        # Local-only provider capability check (never triggers network calls).
        provider_status = self._provider.status()

        # Single deterministic readiness + confirmed snapshot evaluation shared across all ASIs.
        readiness_report = assess_target_readiness(
            target_id=request.target_id,
            catalog=self._catalog,
            application_contexts=self._application_contexts,
            policy_store=self._policy_store,
            selected_asi=asi_order,
            requested_scopes=request.requested_scopes or None,
            policy_ids_by_asi=request.policy_ids_by_asi or None,
        )
        snapshot = readiness_report.snapshot

        asi_results: dict[AsiCode, AsiGenerationResult] = {}
        cross_asi_seen: dict[str, CrossAsiDuplicateReference] = {}
        budget = _GenerationBudgetTracker()

        for asi_code in asi_order:
            _raise_if_cancelled(cancel_event, f"generator_cancelled_before_{asi_code.lower()}")
            asi_results[asi_code] = self._generate_single_asi(
                generation_id=resolved_gen_id,
                asi_code=asi_code,
                requested_count=validated_counts[asi_code],
                snapshot=snapshot,
                assessment=readiness_report.asi_assessments[asi_code],
                request=request,
                token_ceiling=provider_status.max_output_tokens_ceiling,
                cross_asi_seen=cross_asi_seen,
                budget=budget,
                cancel_event=cancel_event,
            )
            _raise_if_cancelled(cancel_event, f"generator_cancelled_after_{asi_code.lower()}")

        all_accepted: list[AcceptedCandidate] = []
        all_rejected: list[RejectedCandidateRecord] = []
        for asi_code in asi_order:
            all_accepted.extend(asi_results[asi_code].accepted_candidates)
            all_rejected.extend(asi_results[asi_code].rejected_candidates)

        total_requested = sum(validated_counts.values())
        total_generated = sum(res.generated_count for res in asi_results.values())
        total_accepted = len(all_accepted)
        total_rejected = len(all_rejected)
        total_call_count = sum(res.call_count for res in asi_results.values())
        total_duration_ms = sum(res.duration_ms for res in asi_results.values())
        total_token_usage = _sum_token_usages([res.token_usage for res in asi_results.values()])
        overall_status = _compute_overall_status(asi_results)

        return GenerationResult(
            generation_id=resolved_gen_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            target_id=request.target_id,
            target_revision_sha256=snapshot.target_revision_sha256 if snapshot is not None else None,
            application_context_revision_sha256=(
                snapshot.application_context_revision_sha256 if snapshot is not None else None
            ),
            context_snapshot_sha256=snapshot.snapshot_sha256 if snapshot is not None else None,
            language=request.language,
            provider_id=provider_status.provider_id,
            model=provider_status.model,
            deduplicate_across_asi=request.deduplicate_across_asi,
            max_calls_per_asi=request.max_calls_per_asi,
            overall_status=overall_status,
            meets_requested_counts=(
                overall_status == "completed" and total_accepted == total_requested
            ),
            has_accepted_candidates=total_accepted > 0,
            total_requested=total_requested,
            total_generated=total_generated,
            total_accepted=total_accepted,
            total_rejected=total_rejected,
            total_call_count=total_call_count,
            total_duration_ms=total_duration_ms,
            total_token_usage=total_token_usage,
            authorized_output_token_budget=budget.output_token_budget,
            allocated_output_tokens=budget.allocated_output_tokens,
            token_usage_unreported_calls=budget.unreported_usage_calls,
            asi_order=asi_order,
            asi_results=asi_results,
            explicit_policy_ids_by_asi=dict(request.policy_ids_by_asi),
            accepted_candidates=tuple(all_accepted),
            rejection_reason_counts=_count_reasons(all_rejected),
        )
