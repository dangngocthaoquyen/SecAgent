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
import re
from typing import Any, Literal, Mapping, Sequence
from uuid import uuid4

from pydantic import Field, field_validator

from generator.constants import (
    ASI_CODE_TO_CATEGORY,
    AsiCategory,
    AsiCode,
    DEFAULT_PER_ASI,
    SUPPORTED_ASI_CODES,
)
from generator.deduplication import (
    CrossAsiDuplicateReference,
    DEDUPLICATION_METHOD_V1,
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
    call_count: int = Field(default=0, ge=0, le=2, strict=True)
    duration_ms: float = Field(default=0.0, ge=0.0, allow_inf_nan=False)
    token_usage: TokenUsage | None = None
    provenance_inputs: GenerationProvenanceInputs | None = None


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


class GeneratorService:
    """Stateless Context-aware Generator Service (G11.3B).

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

    def _invoke_provider_bounded(
        self,
        provider_request: ProviderGenerationRequest,
        *,
        max_calls: int,
    ) -> tuple[ProviderGenerationResponse, int, float, TokenUsage | None]:
        """Execute 1 call by default (max 2 if explicitly configured) with zero fallback."""
        total_calls = 0
        total_duration_ms = 0.0
        usages: list[TokenUsage | None] = []
        last_response: ProviderGenerationResponse | None = None

        for attempt in range(max_calls):
            response = self._provider.generate(provider_request)
            last_response = response
            total_calls += response.call_count
            total_duration_ms += response.duration_ms
            usages.append(response.token_usage)

            if attempt + 1 >= max_calls or not _is_retryable_provider_response(response):
                break

        assert last_response is not None
        return last_response, total_calls, total_duration_ms, _sum_token_usages(usages)

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
    ) -> AsiGenerationResult:
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
            )

        # 2. Load allowlisted Generation Skill bundle.
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
            )

        # 3. Build strictly allowlisted, sanitized provider request.
        try:
            envelope = build_sanitized_generation_request(
                skill_bundle=skill_bundle,
                snapshot=snapshot,
                assessment=assessment,
                requested_count=requested_count,
                language=request.language,
                focus_note=request.focus_note,
                token_ceiling=token_ceiling,
                limits=self._limits,
                request_id=f"{generation_id}-{asi_code.lower()}",
                extra_sensitive_values=request.extra_sensitive_values,
            )
        except GenerationRequestError as exc:
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
            )

        provider_req = envelope.provider_request
        if request.timeout_seconds is not None:
            provider_req = provider_req.model_copy(update={"timeout_seconds": request.timeout_seconds})

        prov = envelope.provenance_inputs

        # 4. Invoke GeneratorLLMProvider under strict call budget.
        response, call_count, duration_ms, token_usage = self._invoke_provider_bounded(
            provider_req,
            max_calls=request.max_calls_per_asi,
        )

        common_kwargs: dict[str, Any] = {
            "asi_code": asi_code,
            "asi_category": category,
            "effective_scope": prov.effective_scope,
            "readiness_status": assessment.status,
            "readiness_blockers": assessment.blockers,
            "readiness_warnings": assessment.warnings,
            "requested_count": requested_count,
            "finish_reason": response.finish_reason,
            "provider_id": response.provider_id,
            "model": response.model,
            "skill_id": prov.skill_id,
            "skill_version": prov.skill_version,
            "skill_sha256": prov.skill_sha256,
            "sanitized_request_sha256": prov.request_sha256,
            "reviewed_policy_id": prov.reviewed_policy_id,
            "reviewed_policy_revision_sha256": prov.reviewed_policy_revision_sha256,
            "call_count": call_count,
            "duration_ms": duration_ms,
            "token_usage": token_usage,
            "provenance_inputs": prov,
        }

        # 5. Classify truncated / provider error outcomes before JSON parsing.
        if (
            response.error_category == ProviderErrorCategory.TRUNCATED_RESPONSE
            or (isinstance(response.finish_reason, str) and response.finish_reason.strip().lower() == "length")
        ):
            return AsiGenerationResult(
                status="truncated",
                error_code="truncated_output",
                error_message=(
                    response.error_message
                    or "LLM generation output was truncated before completion (finish_reason=length)."
                )[:512],
                provider_error_category=response.error_category or ProviderErrorCategory.TRUNCATED_RESPONSE,
                **common_kwargs,
            )

        if not response.ok:
            err_cat = response.error_category or ProviderErrorCategory.HTTP_ERROR
            return AsiGenerationResult(
                status="provider_error",
                error_code=f"provider_error:{err_cat.value}",
                error_message=(response.error_message or "Generator provider call failed.")[:512],
                provider_error_category=err_cat,
                **common_kwargs,
            )

        # 6. Strictly parse untrusted raw_text into RawGenerationOutputContract.
        try:
            parsed = parse_llm_generation_output(
                response.raw_text,
                finish_reason=response.finish_reason,
                max_raw_bytes=self._max_raw_output_bytes,
                max_depth=self._max_json_depth,
            )
        except OutputParseError as exc:
            status: AsiGenerationStatus = "truncated" if exc.code == "truncated_output" else "invalid_output"
            return AsiGenerationResult(
                status=status,
                error_code=exc.code,
                error_message=exc.message[:512],
                **common_kwargs,
            )

        contract = parsed.contract
        generated_count = len(contract.candidates)

        # 7. Deterministic backend candidate validation (ASI consistency + confirmed context_basis).
        val_outcome = validate_parsed_output(
            contract,
            expected_asi_code=asi_code,
            snapshot=snapshot,
            assessment=assessment,
            provenance_inputs=prov,
        )
        if not val_outcome.asi_matched:
            return AsiGenerationResult(
                status="invalid_output",
                generated_count=generated_count,
                error_code="asi_mismatch",
                error_message=(
                    val_outcome.asi_mismatch_message
                    or f"LLM output ASI category does not match requested {asi_code}."
                )[:512],
                **common_kwargs,
            )

        # Explicit empty candidates with valid context_gaps (NEVER treated as completed!).
        if generated_count == 0:
            return AsiGenerationResult(
                status="empty_with_context_gaps",
                generated_count=0,
                accepted_count=0,
                rejected_count=0,
                context_gaps=contract.context_gaps,
                **common_kwargs,
            )

        # 8. Deterministic exact/normalized deduplication (v1).
        dedup_outcome = deduplicate_asi_candidates(
            val_outcome.valid_candidates,
            asi_code=asi_code,
            cross_asi_seen=cross_asi_seen,
            deduplicate_across_asi=request.deduplicate_across_asi,
        )

        # 9. Cap accepted candidates at requested_count WITHOUT silent truncation.
        kept_within_limit = dedup_outcome.kept[:requested_count]
        excess_over_requested = dedup_outcome.kept[requested_count:]

        accepted: list[AcceptedCandidate] = []
        source_index_to_candidate_id: dict[int, str] = {}
        for seq, item in enumerate(kept_within_limit, start=1):
            candidate_id = f"{generation_id}:{asi_code.lower()}:{seq:03d}"
            source_index_to_candidate_id[item.source_index] = candidate_id
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
            # Register accepted candidate in cross-ASI dedup index after minting its backend ID.
            if item.normalized_prompt_sha256 not in cross_asi_seen:
                cross_asi_seen[item.normalized_prompt_sha256] = CrossAsiDuplicateReference(
                    asi_code=asi_code,
                    source_index=item.source_index,
                    candidate_id=candidate_id,
                )

        rejected: list[RejectedCandidateRecord] = []
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

        for dup in dedup_outcome.rejected:
            ref_candidate_id = dup.duplicate_of_candidate_id
            if ref_candidate_id is None and dup.duplicate_of_asi_code == asi_code:
                ref_candidate_id = source_index_to_candidate_id.get(dup.duplicate_of_source_index)
            rejected.append(
                RejectedCandidateRecord(
                    source_index=dup.source_index,
                    asi_code=asi_code,
                    reason_code=dup.reason_code,
                    reason_message=dup.reason_message,
                    prompt_sha256=dup.prompt_sha256,
                    normalized_prompt_sha256=dup.normalized_prompt_sha256,
                    duplicate_of_asi_code=dup.duplicate_of_asi_code,
                    duplicate_of_source_index=dup.duplicate_of_source_index,
                    duplicate_of_candidate_id=ref_candidate_id,
                )
            )

        for extra_item in excess_over_requested:
            rejected.append(
                RejectedCandidateRecord(
                    source_index=extra_item.source_index,
                    asi_code=asi_code,
                    reason_code="exceeds_requested_count",
                    reason_message=(
                        f"Candidate exceeds requested_count ({requested_count}) for {asi_code}; "
                        "explicitly rejected instead of silently truncating."
                    ),
                    prompt_sha256=extra_item.prompt_sha256,
                    normalized_prompt_sha256=extra_item.normalized_prompt_sha256,
                )
            )

        rejected.sort(key=lambda r: r.source_index)
        accepted_count = len(accepted)
        rejected_count = len(rejected)

        if accepted_count == requested_count:
            asi_status: AsiGenerationStatus = "completed"
        elif accepted_count > 0:
            asi_status = "partial"
        else:
            asi_status = "empty_all_rejected"

        return AsiGenerationResult(
            status=asi_status,
            generated_count=generated_count,
            pre_dedup_valid_count=dedup_outcome.pre_dedup_count,
            post_dedup_valid_count=dedup_outcome.post_dedup_count,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            duplicate_rejected_count=(
                dedup_outcome.within_asi_duplicates_removed
                + dedup_outcome.across_asi_duplicates_removed
            ),
            accepted_candidates=tuple(accepted),
            rejected_candidates=tuple(rejected),
            rejection_reason_counts=_count_reasons(rejected),
            context_gaps=contract.context_gaps,
            **common_kwargs,
        )

    def generate(
        self,
        request: GenerationServiceRequest,
        *,
        generation_id: str | None = None,
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

        for asi_code in asi_order:
            asi_results[asi_code] = self._generate_single_asi(
                generation_id=resolved_gen_id,
                asi_code=asi_code,
                requested_count=validated_counts[asi_code],
                snapshot=snapshot,
                assessment=readiness_report.asi_assessments[asi_code],
                request=request,
                token_ceiling=provider_status.max_output_tokens_ceiling,
                cross_asi_seen=cross_asi_seen,
            )

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
            asi_order=asi_order,
            asi_results=asi_results,
            explicit_policy_ids_by_asi=dict(request.policy_ids_by_asi),
            accepted_candidates=tuple(all_accepted),
            rejection_reason_counts=_count_reasons(all_rejected),
        )
