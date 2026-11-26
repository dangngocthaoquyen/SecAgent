"""Bounded in-memory Preview Store, operator edit/selection, and explicit Dataset save (G11.3C).

Responsibilities:
- Store ephemeral `GenerationResult` snapshots before explicit operator Save (never auto-persists).
- Bind each preview to backend-minted `preview_id`, `generation_id`, `target_id`,
  Target/Context/Policy revisions, and operator ownership digest.
- Enforce TTL expiration, capacity bounds, and thread-safe concurrency locks.
- Preserve AI-generated originals separately from operator edits (`ai_generated_original` vs
  `operator_edited`), recomputing `effective_prompt_sha256` on edit while keeping
  `original_prompt_sha256`, ASI taxonomy, effective scope, and provenance immutable.
- Perform explicit Save through SecAgent's existing `normalize_dataset()` and
  `DatasetRepository.save_dataset()`, with fresh revision revalidation, partial-save
  confirmation, idempotency, and rollback safety on persistence failure.
- Process restart clears unsaved in-memory previews; already-saved datasets remain persisted
  in `DatasetRepository`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from threading import RLock
import time
from typing import Any, Callable, Literal, Sequence
from uuid import uuid4

from pydantic import Field, field_validator

from generator.constants import (
    AsiCategory,
    AsiCode,
    GENERATOR_SOURCE_TOOL,
    MAX_CANDIDATE_PROMPT_UTF8_BYTES,
)
from generator.deduplication import compute_prompt_sha256
from generator.models import StrictGeneratorModel
from generator.providers.base import TokenUsage
from generator.readiness import build_context_snapshot
from generator.request_builder import SupportedLanguage
from generator.service import (
    AcceptedCandidate,
    GenerationResult,
    OverallGenerationStatus,
)
from workflow.dataset_normalizer import DatasetValidationError, normalize_dataset
from workflow.dataset_repository import DatasetRepository

DEFAULT_PREVIEW_TTL_SECONDS: float = 1800.0  # 30 minutes
DEFAULT_MAX_PREVIEWS: int = 32
MAX_DATASET_NAME_CHARS: int = 120

PreviewStatus = Literal["active", "saved", "expired"]
PreviewCandidateOrigin = Literal["ai_generated_original", "operator_edited"]

_PREVIEW_ID_RE = re.compile(r"^prev-[a-f0-9]{32}$")
_SAFE_NAME_RE = re.compile(r"[^\w\s.-]")


class PreviewStoreError(ValueError):
    """Structured, secret-free error raised for preview lifecycle, edit, or save failures."""

    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class PreviewCandidateView(StrictGeneratorModel):
    """Public preview representation distinguishing AI-generated original vs operator-edited copy."""

    candidate_id: str = Field(min_length=8, max_length=96)
    candidate_id_scope: Literal["ephemeral_generation_candidate"] = "ephemeral_generation_candidate"
    asi_code: AsiCode
    asi_category: AsiCategory
    effective_scope: str = Field(min_length=1, max_length=128)
    source_index: int = Field(ge=0, strict=True)
    origin: PreviewCandidateOrigin
    operator_edited: bool
    selected: bool
    original_prompt: str = Field(min_length=1)
    original_description: str = Field(min_length=1, max_length=512)
    original_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    effective_prompt: str = Field(min_length=1)
    effective_description: str = Field(min_length=1, max_length=512)
    effective_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    strategy_tag: str = Field(min_length=2, max_length=64)
    context_basis: tuple[str, ...] = Field(min_length=1)
    scope_note: str = Field(min_length=1, max_length=512)
    reviewed_policy_id: str | None = None
    reviewed_policy_revision_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class PreviewCandidateEditItem(StrictGeneratorModel):
    """Strict operator edit/selection patch for a single preview candidate.

    Uses `extra='forbid'` so clients cannot alter ASI category, effective scope,
    reviewed policy, original hash, origin, verdicts, assertions, or evaluation rules.
    """

    candidate_id: str = Field(min_length=8, max_length=96)
    selected: bool | None = Field(default=None, strict=True)
    prompt: str | None = Field(default=None, min_length=1, max_length=MAX_CANDIDATE_PROMPT_UTF8_BYTES)
    description: str | None = Field(default=None, min_length=1, max_length=512)
    reset_to_original: bool = Field(default=False, strict=True)

    @field_validator("candidate_id")
    @classmethod
    def check_candidate_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("candidate_id must not be blank.")
        return cleaned

    @field_validator("prompt")
    @classmethod
    def check_prompt_bounds(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value.encode("utf-8")) > MAX_CANDIDATE_PROMPT_UTF8_BYTES:
            raise ValueError(
                f"Edited prompt exceeds {MAX_CANDIDATE_PROMPT_UTF8_BYTES} UTF-8 bytes."
            )
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Edited prompt must not be blank.")
        if len(cleaned.encode("utf-8")) > MAX_CANDIDATE_PROMPT_UTF8_BYTES:
            raise ValueError(
                f"Edited prompt exceeds {MAX_CANDIDATE_PROMPT_UTF8_BYTES} UTF-8 bytes."
            )
        return cleaned

    @field_validator("description")
    @classmethod
    def check_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Edited description must not be blank.")
        return cleaned


class PreviewEditRequest(StrictGeneratorModel):
    """Operator preview update request containing one or more candidate edits/selections."""

    edits: tuple[PreviewCandidateEditItem, ...] = Field(min_length=1, max_length=50)


class PreviewSaveRequest(StrictGeneratorModel):
    """Explicit operator confirmation request to persist selected preview candidates."""

    dataset_name: str = Field(min_length=1, max_length=MAX_DATASET_NAME_CHARS)
    selected_candidate_ids: tuple[str, ...] | None = Field(default=None, min_length=1, max_length=50)
    save_confirmed: bool = Field(strict=True)
    partial_save_confirmed: bool = Field(default=False, strict=True)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=96)

    @field_validator("dataset_name")
    @classmethod
    def check_dataset_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("dataset_name must not be blank.")
        return cleaned

    @field_validator("selected_candidate_ids")
    @classmethod
    def check_selected_ids(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            token = item.strip()
            if not token:
                raise ValueError("selected_candidate_ids entries must not be blank.")
            if token in seen:
                raise ValueError("Duplicate candidate_id in selected_candidate_ids.")
            seen.add(token)
            cleaned.append(token)
        return tuple(cleaned)


class PreviewSaveRecord(StrictGeneratorModel):
    """Immutable record returned after explicit persistence into DatasetRepository."""

    save_status: Literal["saved"] = "saved"
    dataset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    dataset_name: str = Field(min_length=1, max_length=160)
    dataset_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    saved_at: str = Field(min_length=10, max_length=64)
    created: bool
    idempotent_replay: bool = False
    saved_candidate_ids: tuple[str, ...] = Field(min_length=1)
    saved_count: int = Field(ge=1, strict=True)
    requested_count: int = Field(ge=1, strict=True)
    generated_count: int = Field(ge=0, strict=True)
    accepted_count: int = Field(ge=0, strict=True)
    rejected_count: int = Field(ge=0, strict=True)
    selected_for_save_count: int = Field(ge=1, strict=True)
    partial_generation: bool
    partial_save_confirmed: bool
    meets_requested_counts: bool
    save_request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class GeneratorPreviewSnapshot(StrictGeneratorModel):
    """Secret-free, immutable snapshot of a Preview Store entry returned to API callers."""

    preview_id: str = Field(pattern=r"^prev-[a-f0-9]{32}$")
    status: PreviewStatus
    created_at: str
    updated_at: str
    expires_at: str
    generation_id: str
    target_id: str
    target_revision_sha256: str | None = None
    application_context_revision_sha256: str | None = None
    context_snapshot_sha256: str | None = None
    reviewed_policy_revisions: dict[AsiCode, dict[str, str]] = Field(default_factory=dict)
    provider_id: str
    model: str
    language: SupportedLanguage
    deduplicate_across_asi: bool
    overall_status: OverallGenerationStatus
    meets_requested_counts: bool
    has_accepted_candidates: bool
    can_save: bool
    requires_partial_confirmation: bool
    total_requested: int
    total_generated: int
    total_accepted: int
    total_rejected: int
    selected_count: int
    edited_count: int
    total_call_count: int
    total_duration_ms: float
    total_token_usage: TokenUsage | None = None
    asi_order: tuple[AsiCode, ...]
    asi_summaries: dict[AsiCode, dict[str, Any]]
    candidates: tuple[PreviewCandidateView, ...]
    rejection_reason_counts: dict[str, int] = Field(default_factory=dict)
    save_record: PreviewSaveRecord | None = None
    auto_persisted: Literal[False] = False
    auto_executed: Literal[False] = False


class _MutableCandidateState:
    __slots__ = (
        "original",
        "reviewed_policy_id",
        "reviewed_policy_revision_sha256",
        "selected",
        "effective_prompt",
        "effective_description",
        "effective_prompt_sha256",
    )

    def __init__(
        self,
        original: AcceptedCandidate,
        *,
        reviewed_policy_id: str | None,
        reviewed_policy_revision_sha256: str | None,
    ) -> None:
        self.original = original
        self.reviewed_policy_id = reviewed_policy_id
        self.reviewed_policy_revision_sha256 = reviewed_policy_revision_sha256
        self.selected: bool = True
        self.effective_prompt: str = original.prompt
        self.effective_description: str = original.description
        self.effective_prompt_sha256: str = original.prompt_sha256

    @property
    def operator_edited(self) -> bool:
        return (
            self.effective_prompt != self.original.prompt
            or self.effective_description != self.original.description
        )

    def to_view(self) -> PreviewCandidateView:
        edited = self.operator_edited
        return PreviewCandidateView(
            candidate_id=self.original.candidate_id,
            asi_code=self.original.asi_code,
            asi_category=self.original.asi_category,
            effective_scope=self.original.effective_scope,
            source_index=self.original.source_index,
            origin="operator_edited" if edited else "ai_generated_original",
            operator_edited=edited,
            selected=self.selected,
            original_prompt=self.original.prompt,
            original_description=self.original.description,
            original_prompt_sha256=self.original.prompt_sha256,
            effective_prompt=self.effective_prompt,
            effective_description=self.effective_description,
            effective_prompt_sha256=self.effective_prompt_sha256,
            strategy_tag=self.original.strategy_tag,
            context_basis=self.original.context_basis,
            scope_note=self.original.scope_note,
            reviewed_policy_id=self.reviewed_policy_id,
            reviewed_policy_revision_sha256=self.reviewed_policy_revision_sha256,
        )


class _PreviewEntry:
    def __init__(
        self,
        *,
        preview_id: str,
        owner_digest: str,
        result: GenerationResult,
        created_mono: float,
        expires_mono: float,
        created_wall: datetime,
        expires_wall: datetime,
    ) -> None:
        self.preview_id = preview_id
        self.owner_digest = owner_digest
        self.result = result
        self.created_mono = created_mono
        self.expires_mono = expires_mono
        self.created_at = created_wall.isoformat()
        self.updated_at = self.created_at
        self.expires_at = expires_wall.isoformat()
        self.saving: bool = False
        self.save_record: PreviewSaveRecord | None = None
        self.candidates: dict[str, _MutableCandidateState] = {}
        self.candidate_order: list[str] = []

        for asi_code in result.asi_order:
            asi_res = result.asi_results[asi_code]
            for cand in asi_res.accepted_candidates:
                self.candidates[cand.candidate_id] = _MutableCandidateState(
                    cand,
                    reviewed_policy_id=asi_res.reviewed_policy_id,
                    reviewed_policy_revision_sha256=asi_res.reviewed_policy_revision_sha256,
                )
                self.candidate_order.append(cand.candidate_id)

    def reviewed_policy_revisions(self) -> dict[AsiCode, dict[str, str]]:
        out: dict[AsiCode, dict[str, str]] = {}
        for asi_code in self.result.asi_order:
            asi_res = self.result.asi_results[asi_code]
            if asi_res.reviewed_policy_id and asi_res.reviewed_policy_revision_sha256:
                out[asi_code] = {
                    "policy_id": asi_res.reviewed_policy_id,
                    "revision_sha256": asi_res.reviewed_policy_revision_sha256,
                }
        return out

    def status_at(self, now_mono: float) -> PreviewStatus:
        if self.save_record is not None:
            return "saved"
        if now_mono >= self.expires_mono:
            return "expired"
        return "active"

    def to_snapshot(self, now_mono: float) -> GeneratorPreviewSnapshot:
        status = self.status_at(now_mono)
        views = tuple(self.candidates[cid].to_view() for cid in self.candidate_order)
        selected_count = sum(1 for v in views if v.selected)
        edited_count = sum(1 for v in views if v.operator_edited)
        has_accepted = len(views) > 0
        asi_summaries: dict[AsiCode, dict[str, Any]] = {}
        for code in self.result.asi_order:
            r = self.result.asi_results[code]
            asi_summaries[code] = {
                "asi_code": r.asi_code,
                "asi_category": r.asi_category,
                "status": r.status,
                "effective_scope": r.effective_scope,
                "readiness_status": r.readiness_status,
                "readiness_blockers": list(r.readiness_blockers),
                "readiness_warnings": list(r.readiness_warnings),
                "requested_count": r.requested_count,
                "generated_count": r.generated_count,
                "accepted_count": r.accepted_count,
                "rejected_count": r.rejected_count,
                "duplicate_rejected_count": r.duplicate_rejected_count,
                "rejection_reason_counts": dict(r.rejection_reason_counts),
                "context_gaps": list(r.context_gaps),
                "error_code": r.error_code,
                "error_message": r.error_message,
                "skill_id": r.skill_id,
                "skill_version": r.skill_version,
                "skill_sha256": r.skill_sha256,
                "sanitized_request_sha256": r.sanitized_request_sha256,
                "reviewed_policy_id": r.reviewed_policy_id,
                "reviewed_policy_revision_sha256": r.reviewed_policy_revision_sha256,
                "call_count": r.call_count,
                "duration_ms": r.duration_ms,
            }

        return GeneratorPreviewSnapshot(
            preview_id=self.preview_id,
            status=status,
            created_at=self.created_at,
            updated_at=self.updated_at,
            expires_at=self.expires_at,
            generation_id=self.result.generation_id,
            target_id=self.result.target_id,
            target_revision_sha256=self.result.target_revision_sha256,
            application_context_revision_sha256=self.result.application_context_revision_sha256,
            context_snapshot_sha256=self.result.context_snapshot_sha256,
            reviewed_policy_revisions=self.reviewed_policy_revisions(),
            provider_id=self.result.provider_id,
            model=self.result.model,
            language=self.result.language,
            deduplicate_across_asi=self.result.deduplicate_across_asi,
            overall_status=self.result.overall_status,
            meets_requested_counts=self.result.meets_requested_counts,
            has_accepted_candidates=has_accepted,
            can_save=(status == "active" and has_accepted),
            requires_partial_confirmation=(has_accepted and not self.result.meets_requested_counts),
            total_requested=self.result.total_requested,
            total_generated=self.result.total_generated,
            total_accepted=self.result.total_accepted,
            total_rejected=self.result.total_rejected,
            selected_count=selected_count,
            edited_count=edited_count,
            total_call_count=self.result.total_call_count,
            total_duration_ms=self.result.total_duration_ms,
            total_token_usage=self.result.total_token_usage,
            asi_order=self.result.asi_order,
            asi_summaries=asi_summaries,
            candidates=views,
            rejection_reason_counts=dict(self.result.rejection_reason_counts),
            save_record=self.save_record,
        )


def _hash_owner_id(owner_id: str) -> str:
    if not isinstance(owner_id, str) or not owner_id.strip():
        raise PreviewStoreError(
            "operator_authentication_required",
            "A valid operator session identity is required for preview access.",
            status_code=403,
        )
    return sha256(owner_id.strip().encode("utf-8")).hexdigest()


def _sanitize_dataset_filename(dataset_name: str) -> str:
    """Clean dataset name and ensure normalize_dataset() always parses as canonical JSON."""
    cleaned = _SAFE_NAME_RE.sub("", dataset_name).strip()[:MAX_DATASET_NAME_CHARS]
    if not cleaned:
        cleaned = "generated-dataset.json"
    lower = cleaned.lower()
    if lower.endswith((".yaml", ".yml", ".jsonl")):
        cleaned = cleaned + ".json"
    return cleaned


def _compute_save_request_digest(
    *,
    dataset_name: str,
    selected_views: Sequence[PreviewCandidateView],
    partial_save_confirmed: bool,
    idempotency_key: str | None,
) -> str:
    material = {
        "dataset_name": dataset_name,
        "partial_save_confirmed": partial_save_confirmed,
        "idempotency_key": idempotency_key,
        "candidates": [
            {
                "candidate_id": v.candidate_id,
                "effective_prompt_sha256": v.effective_prompt_sha256,
                "effective_description": v.effective_description,
            }
            for v in selected_views
        ],
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def serialize_preview_candidates_to_dataset_json(
    *,
    preview_id: str | None,
    result: GenerationResult,
    selected_views: Sequence[PreviewCandidateView],
    partial_save_confirmed: bool,
    workflow_id: str | None = None,
    auto_persisted: bool = False,
) -> bytes:
    """Build backend-controlled canonical dataset JSON compatible with normalize_dataset()."""
    selected_asi_codes = {v.asi_code for v in selected_views}
    asi_skills: dict[str, dict[str, Any]] = {}
    reviewed_policies: dict[str, dict[str, str]] = {}

    for code in result.asi_order:
        if code not in selected_asi_codes:
            continue
        asi_res = result.asi_results[code]
        asi_skills[code] = {
            "skill_id": asi_res.skill_id,
            "skill_version": asi_res.skill_version,
            "skill_sha256": asi_res.skill_sha256,
            "sanitized_request_sha256": asi_res.sanitized_request_sha256,
            "effective_scope_metadata": asi_res.effective_scope,
        }
        if asi_res.reviewed_policy_id and asi_res.reviewed_policy_revision_sha256:
            reviewed_policies[code] = {
                "policy_id": asi_res.reviewed_policy_id,
                "revision_sha256": asi_res.reviewed_policy_revision_sha256,
            }

    testcases: list[dict[str, Any]] = []
    for idx, view in enumerate(selected_views, start=1):
        meta: dict[str, Any] = {
            "asi_category": view.asi_category,
            "owasp_asi": view.asi_code,
            "source": GENERATOR_SOURCE_TOOL,
            "origin": view.origin,
            "operator_edited": view.operator_edited,
            "generation_id": result.generation_id,
            "source_candidate_id": view.candidate_id,
            "target_id": result.target_id,
            "original_prompt_sha256": view.original_prompt_sha256,
            "effective_prompt_sha256": view.effective_prompt_sha256,
            "context_basis": list(view.context_basis),
            # Metadata only: never execution authorization or trusted evaluation rules.
            "effective_scope_metadata": view.effective_scope,
            "scope_note": view.scope_note,
        }
        if preview_id is not None:
            meta["preview_id"] = preview_id
        if workflow_id is not None:
            meta["workflow_id"] = workflow_id
        if view.reviewed_policy_id and view.reviewed_policy_revision_sha256:
            meta["reviewed_policy_id"] = view.reviewed_policy_id
            meta["reviewed_policy_revision_sha256"] = view.reviewed_policy_revision_sha256

        testcases.append(
            {
                "testcase_id": f"G11-{view.asi_code}-{idx:03d}",
                "prompt": view.effective_prompt,
                "description": view.effective_description,
                "plugin_id": view.asi_code.lower(),
                "strategy_id": view.strategy_tag,
                "assertions": [],  # Never emit LLM verdicts or assertions.
                "metadata": meta,
            }
        )

    generation_provenance: dict[str, Any] = {
        "source": "SecAgent AI Generator",
        "generation_id": result.generation_id,
        "preview_id": preview_id,
        "target_id": result.target_id,
        "target_revision_sha256": result.target_revision_sha256,
        "application_context_revision_sha256": result.application_context_revision_sha256,
        "context_snapshot_sha256": result.context_snapshot_sha256,
        "provider_id": result.provider_id,
        "model": result.model,
        "language": result.language,
        "deduplicate_across_asi": result.deduplicate_across_asi,
        "overall_status": result.overall_status,
        "meets_requested_counts": result.meets_requested_counts,
        "partial_generation": not result.meets_requested_counts,
        "partial_save_confirmed": partial_save_confirmed,
        "auto_persisted": auto_persisted,
        "workflow_mode": "generate_and_run" if auto_persisted else "generate_only",
        "counts": {
            "requested": result.total_requested,
            "generated": result.total_generated,
            "accepted": result.total_accepted,
            "rejected": result.total_rejected,
            "selected_for_save": len(selected_views),
        },
        "asi_skills": asi_skills,
        "reviewed_policies": reviewed_policies,
    }
    if workflow_id is not None:
        generation_provenance["workflow_id"] = workflow_id

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "source_tool": GENERATOR_SOURCE_TOOL,
        "platform": "secagent_ai_generator",
        "bot": result.target_id[:64],
        "run_id": result.generation_id[:64],
        "generation_provenance": generation_provenance,
        "testcases": testcases,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def serialize_generation_result_to_dataset_json(
    *,
    result: GenerationResult,
    workflow_id: str,
    partial_execution_confirmed: bool = False,
) -> bytes:
    """Serialize all accepted candidates of a GenerationResult for Mode 1 auto-persistence."""
    views: list[PreviewCandidateView] = []
    for code in result.asi_order:
        asi_res = result.asi_results[code]
        for cand in asi_res.accepted_candidates:
            views.append(
                PreviewCandidateView(
                    candidate_id=cand.candidate_id,
                    asi_code=cand.asi_code,
                    asi_category=cand.asi_category,
                    effective_scope=cand.effective_scope,
                    source_index=cand.source_index,
                    origin="ai_generated_original",
                    operator_edited=False,
                    selected=True,
                    original_prompt=cand.prompt,
                    original_description=cand.description,
                    original_prompt_sha256=cand.prompt_sha256,
                    effective_prompt=cand.prompt,
                    effective_description=cand.description,
                    effective_prompt_sha256=cand.prompt_sha256,
                    strategy_tag=cand.strategy_tag,
                    context_basis=cand.context_basis,
                    scope_note=cand.scope_note,
                    reviewed_policy_id=asi_res.reviewed_policy_id,
                    reviewed_policy_revision_sha256=asi_res.reviewed_policy_revision_sha256,
                )
            )
    return serialize_preview_candidates_to_dataset_json(
        preview_id=None,
        result=result,
        selected_views=views,
        partial_save_confirmed=partial_execution_confirmed,
        workflow_id=workflow_id,
        auto_persisted=True,
    )


class GeneratorPreviewStore:
    """Thread-safe, bounded in-memory preview store with TTL, ownership, and explicit Save."""

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_PREVIEW_TTL_SECONDS,
        max_previews: int = DEFAULT_MAX_PREVIEWS,
        clock: Callable[[], float] | None = None,
        wall_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive number.")
        if isinstance(max_previews, bool) or not isinstance(max_previews, int) or max_previews < 1:
            raise ValueError("max_previews must be a positive integer.")
        self._ttl_seconds = float(ttl_seconds)
        self._max_previews = max_previews
        self._clock = clock or time.monotonic
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._entries: dict[str, _PreviewEntry] = {}

    def _prune_expired_locked(self, now_mono: float) -> None:
        expired_ids = [
            pid
            for pid, entry in self._entries.items()
            if entry.save_record is None and not entry.saving and now_mono >= entry.expires_mono
        ]
        for pid in expired_ids:
            self._entries.pop(pid, None)

    def _validate_preview_id(self, preview_id: str) -> str:
        if not isinstance(preview_id, str) or not _PREVIEW_ID_RE.fullmatch(preview_id.strip()):
            raise PreviewStoreError("preview_not_found", "Preview record was not found.", status_code=404)
        return preview_id.strip()

    def _get_owned_entry_locked(self, preview_id: str, owner_digest: str) -> _PreviewEntry:
        clean_id = self._validate_preview_id(preview_id)
        entry = self._entries.get(clean_id)
        if entry is None:
            raise PreviewStoreError(
                "preview_not_found",
                "Preview record does not exist or was cleared on server restart.",
                status_code=404,
            )
        if entry.owner_digest != owner_digest:
            raise PreviewStoreError(
                "preview_access_denied",
                "Preview belongs to a different operator session.",
                status_code=403,
            )
        return entry

    def create_preview(
        self,
        *,
        result: GenerationResult,
        owner_id: str,
    ) -> GeneratorPreviewSnapshot:
        owner_digest = _hash_owner_id(owner_id)
        with self._lock:
            now_mono = self._clock()
            self._prune_expired_locked(now_mono)

            if len(self._entries) >= self._max_previews:
                # Prefer evicting the oldest already-saved preview before rejecting.
                saved_entries = sorted(
                    (e for e in self._entries.values() if e.save_record is not None and not e.saving),
                    key=lambda e: e.created_mono,
                )
                if saved_entries:
                    self._entries.pop(saved_entries[0].preview_id, None)
                else:
                    raise PreviewStoreError(
                        "preview_capacity_exceeded",
                        f"Maximum active preview capacity ({self._max_previews}) reached; "
                        "save or wait for older previews to expire.",
                        status_code=429,
                    )

            now_wall = self._wall_clock()
            expires_wall = now_wall + timedelta(seconds=self._ttl_seconds)
            preview_id = f"prev-{uuid4().hex}"
            entry = _PreviewEntry(
                preview_id=preview_id,
                owner_digest=owner_digest,
                result=result,
                created_mono=now_mono,
                expires_mono=now_mono + self._ttl_seconds,
                created_wall=now_wall,
                expires_wall=expires_wall,
            )
            self._entries[preview_id] = entry
            return entry.to_snapshot(now_mono)

    def get_preview(self, *, preview_id: str, owner_id: str) -> GeneratorPreviewSnapshot:
        owner_digest = _hash_owner_id(owner_id)
        with self._lock:
            now_mono = self._clock()
            entry = self._get_owned_entry_locked(preview_id, owner_digest)
            if entry.status_at(now_mono) == "expired":
                self._entries.pop(entry.preview_id, None)
                raise PreviewStoreError(
                    "preview_expired",
                    "Preview has expired. Generate a fresh preview before editing or saving.",
                    status_code=410,
                )
            return entry.to_snapshot(now_mono)

    def get_save_status(self, *, preview_id: str, owner_id: str) -> dict[str, Any]:
        snap = self.get_preview(preview_id=preview_id, owner_id=owner_id)
        return {
            "preview_id": snap.preview_id,
            "generation_id": snap.generation_id,
            "preview_status": snap.status,
            "saved": snap.save_record is not None,
            "dataset_id": snap.save_record.dataset_id if snap.save_record is not None else None,
            "save_record": snap.save_record.model_dump(mode="json") if snap.save_record is not None else None,
        }

    def update_preview(
        self,
        *,
        preview_id: str,
        owner_id: str,
        edit_request: PreviewEditRequest,
    ) -> GeneratorPreviewSnapshot:
        owner_digest = _hash_owner_id(owner_id)
        with self._lock:
            now_mono = self._clock()
            entry = self._get_owned_entry_locked(preview_id, owner_digest)
            status = entry.status_at(now_mono)
            if status == "expired":
                self._entries.pop(entry.preview_id, None)
                raise PreviewStoreError(
                    "preview_expired",
                    "Preview has expired and can no longer be edited.",
                    status_code=410,
                )
            if status == "saved":
                raise PreviewStoreError(
                    "preview_already_saved",
                    "Preview was already saved to DatasetRepository and is immutable.",
                    status_code=409,
                )
            if entry.saving:
                raise PreviewStoreError(
                    "preview_save_in_progress",
                    "Preview save is currently in progress.",
                    status_code=409,
                )

            # Validate all candidate_ids first so edits are atomic (all-or-nothing).
            seen_ids: set[str] = set()
            for item in edit_request.edits:
                if item.candidate_id in seen_ids:
                    raise PreviewStoreError(
                        "duplicate_edit_candidate_id",
                        f"Duplicate candidate_id in edit request: {item.candidate_id}.",
                        status_code=400,
                    )
                seen_ids.add(item.candidate_id)
                if item.candidate_id not in entry.candidates:
                    raise PreviewStoreError(
                        "candidate_not_in_preview",
                        "Candidate identifier does not belong to this preview.",
                        status_code=404,
                    )

            for item in edit_request.edits:
                state = entry.candidates[item.candidate_id]
                if item.reset_to_original:
                    state.effective_prompt = state.original.prompt
                    state.effective_description = state.original.description
                    state.effective_prompt_sha256 = state.original.prompt_sha256
                else:
                    if item.prompt is not None:
                        state.effective_prompt = item.prompt
                        state.effective_prompt_sha256 = compute_prompt_sha256(item.prompt)
                    if item.description is not None:
                        state.effective_description = item.description
                if item.selected is not None:
                    state.selected = item.selected

            entry.updated_at = self._wall_clock().isoformat()
            return entry.to_snapshot(now_mono)

    def save_preview(
        self,
        *,
        preview_id: str,
        owner_id: str,
        save_request: PreviewSaveRequest,
        catalog: Any,
        application_contexts: Any | None,
        dataset_repo: DatasetRepository,
        policy_store: Any | None = None,
        normalizer: Callable[[bytes, str], Any] = normalize_dataset,
    ) -> PreviewSaveRecord:
        """Explicitly validate freshness, normalize, and persist selected candidates."""
        owner_digest = _hash_owner_id(owner_id)

        if not save_request.save_confirmed:
            raise PreviewStoreError(
                "save_confirmation_required",
                "Explicit operator save_confirmed=true is required to persist a dataset.",
                status_code=400,
            )

        clean_dataset_name = _sanitize_dataset_filename(save_request.dataset_name)

        # Phase 1 (under lock): validate state, ownership, selection, idempotency, and acquire saving lock.
        with self._lock:
            now_mono = self._clock()
            entry = self._get_owned_entry_locked(preview_id, owner_digest)
            status = entry.status_at(now_mono)
            if status == "expired":
                self._entries.pop(entry.preview_id, None)
                raise PreviewStoreError(
                    "preview_expired",
                    "Preview has expired. Generate a fresh preview before saving.",
                    status_code=410,
                )

            if entry.saving:
                raise PreviewStoreError(
                    "preview_save_in_progress",
                    "A save operation for this preview is already in progress.",
                    status_code=409,
                )

            if not entry.candidate_order:
                raise PreviewStoreError(
                    "preview_has_no_accepted_candidates",
                    "Cannot save an empty dataset; preview has zero accepted candidates.",
                    status_code=409,
                )

            # Resolve selected candidate views in deterministic preview order.
            if save_request.selected_candidate_ids is not None:
                for cid in save_request.selected_candidate_ids:
                    if cid not in entry.candidates:
                        raise PreviewStoreError(
                            "candidate_not_in_preview",
                            "One or more selected_candidate_ids do not belong to this preview.",
                            status_code=400,
                        )
                selected_set = set(save_request.selected_candidate_ids)
                selected_views = tuple(
                    entry.candidates[cid].to_view()
                    for cid in entry.candidate_order
                    if cid in selected_set
                )
            else:
                selected_views = tuple(
                    entry.candidates[cid].to_view()
                    for cid in entry.candidate_order
                    if entry.candidates[cid].selected
                )

            if not selected_views:
                raise PreviewStoreError(
                    "no_candidates_selected",
                    "At least one accepted candidate must be selected before saving.",
                    status_code=400,
                )

            is_partial = not entry.result.meets_requested_counts
            if is_partial and not save_request.partial_save_confirmed:
                raise PreviewStoreError(
                    "partial_save_confirmation_required",
                    "This generation is partial (accepted < requested). Pass "
                    "partial_save_confirmed=true to explicitly save the selected subset.",
                    status_code=409,
                )

            save_digest = _compute_save_request_digest(
                dataset_name=clean_dataset_name,
                selected_views=selected_views,
                partial_save_confirmed=save_request.partial_save_confirmed,
                idempotency_key=save_request.idempotency_key,
            )

            # Idempotent replay vs conflicting repeat save.
            if entry.save_record is not None:
                if entry.save_record.save_request_digest == save_digest:
                    return entry.save_record.model_copy(update={"idempotent_replay": True})
                raise PreviewStoreError(
                    "preview_already_saved",
                    "Preview was already saved with different parameters.",
                    status_code=409,
                )

            entry.saving = True
            gen_result = entry.result
            bound_policy_revs = entry.reviewed_policy_revisions()

        # Phase 2 (outside global lock so concurrent callers receive 409 immediately):
        # Freshness check + canonical serialization + normalize_dataset() + DatasetRepository.save_dataset()
        try:
            self._revalidate_revisions(
                result=gen_result,
                selected_views=selected_views,
                bound_policy_revs=bound_policy_revs,
                catalog=catalog,
                application_contexts=application_contexts,
                policy_store=policy_store,
            )

            raw_bytes = serialize_preview_candidates_to_dataset_json(
                preview_id=entry.preview_id,
                result=gen_result,
                selected_views=selected_views,
                partial_save_confirmed=save_request.partial_save_confirmed,
            )

            try:
                envelope = normalizer(raw_bytes, clean_dataset_name)
            except DatasetValidationError as exc:
                raise PreviewStoreError(
                    f"dataset_normalization_failed:{exc.code}",
                    exc.message[:512],
                    status_code=422,
                ) from None
            except Exception:
                raise PreviewStoreError(
                    "dataset_normalization_failed",
                    "Dataset normalization failed before persistence.",
                    status_code=500,
                ) from None

            try:
                saved_envelope, created = dataset_repo.save_dataset(envelope)
            except Exception:
                raise PreviewStoreError(
                    "dataset_save_failed",
                    "Persisting normalized dataset to DatasetRepository failed; preview remains unsaved.",
                    status_code=500,
                ) from None

            record = PreviewSaveRecord(
                dataset_id=saved_envelope.dataset_id,
                dataset_name=saved_envelope.name,
                dataset_file_sha256=saved_envelope.file_sha256,
                dataset_content_sha256=saved_envelope.content_sha256,
                saved_at=self._wall_clock().isoformat(),
                created=created,
                idempotent_replay=False,
                saved_candidate_ids=tuple(v.candidate_id for v in selected_views),
                saved_count=saved_envelope.total_testcases,
                requested_count=gen_result.total_requested,
                generated_count=gen_result.total_generated,
                accepted_count=gen_result.total_accepted,
                rejected_count=gen_result.total_rejected,
                selected_for_save_count=len(selected_views),
                partial_generation=is_partial,
                partial_save_confirmed=save_request.partial_save_confirmed,
                meets_requested_counts=gen_result.meets_requested_counts,
                save_request_digest=save_digest,
            )

            with self._lock:
                entry.save_record = record
                entry.updated_at = record.saved_at
                entry.saving = False
            return record
        except Exception:
            with self._lock:
                entry.saving = False
            raise

    def _revalidate_revisions(
        self,
        *,
        result: GenerationResult,
        selected_views: Sequence[PreviewCandidateView],
        bound_policy_revs: dict[AsiCode, dict[str, str]],
        catalog: Any,
        application_contexts: Any | None,
        policy_store: Any | None,
    ) -> None:
        """Fail closed if Target, Application Context, or bound Reviewed Policy changed since generation."""
        selected_asi_codes = {v.asi_code for v in selected_views}
        selected_policy_ids: dict[AsiCode, str] = {
            code: info["policy_id"]
            for code, info in bound_policy_revs.items()
            if code in selected_asi_codes
        }

        current_snapshot = build_context_snapshot(
            target_id=result.target_id,
            catalog=catalog,
            application_contexts=application_contexts,
            policy_store=policy_store,
            policy_ids_by_asi=selected_policy_ids or None,
        )
        if current_snapshot is None:
            raise PreviewStoreError(
                "preview_target_not_found",
                "Target profile no longer exists in the catalog; cannot save stale preview.",
                status_code=409,
            )

        if current_snapshot.target_revision_sha256 != result.target_revision_sha256:
            raise PreviewStoreError(
                "preview_target_revision_stale",
                "Target profile revision changed after generation. Generate a fresh preview before saving.",
                status_code=409,
            )

        if (
            current_snapshot.application_context_binding_status != "current"
            or current_snapshot.application_context_revision_sha256 != result.application_context_revision_sha256
        ):
            raise PreviewStoreError(
                "preview_context_revision_stale",
                "Application Context revision changed or became stale after generation. "
                "Generate a fresh preview before saving.",
                status_code=409,
            )

        for code, expected_id in selected_policy_ids.items():
            expected_rev = bound_policy_revs[code]["revision_sha256"]
            current_pol = current_snapshot.reviewed_policies.get(code)
            if (
                current_pol is None
                or current_pol.policy_id != expected_id
                or current_pol.revision_sha256 != expected_rev
            ):
                raise PreviewStoreError(
                    "preview_policy_revision_stale",
                    f"Reviewed ResponsePolicy for {code} changed or is no longer reviewed. "
                    "Generate a fresh preview before saving.",
                    status_code=409,
                )

        # Also detect newly reviewed policies added for selected ASIs after generation.
        if policy_store is not None:
            unpinned_snapshot = build_context_snapshot(
                target_id=result.target_id,
                catalog=catalog,
                application_contexts=application_contexts,
                policy_store=policy_store,
                policy_ids_by_asi=None,
            )
            if unpinned_snapshot is not None:
                for code in selected_asi_codes:
                    expected_info = bound_policy_revs.get(code)
                    live_pol = unpinned_snapshot.reviewed_policies.get(code)
                    live_ambig = unpinned_snapshot.ambiguous_policy_candidates.get(code, ())
                    if expected_info is None and (live_pol is not None or live_ambig):
                        raise PreviewStoreError(
                            "preview_policy_revision_stale",
                            f"A new Reviewed ResponsePolicy was added for {code} after generation. "
                            "Generate a fresh preview before saving.",
                            status_code=409,
                        )
                    if expected_info is not None and live_ambig and len(live_ambig) > 1:
                        # Only reject ambiguity growth when the operator did NOT explicitly pin a
                        # policy at generation time (e.g., a second policy was added after a
                        # single-policy generation). When the operator explicitly pinned a policy
                        # in a multi-policy target, lines 1063-1076 already verified its exact
                        # policy_id and revision_sha256 remain reviewed and unchanged.
                        if code not in result.explicit_policy_ids_by_asi:
                            raise PreviewStoreError(
                                "preview_policy_revision_stale",
                                f"Reviewed ResponsePolicy set for {code} changed after generation. "
                                "Generate a fresh preview before saving.",
                                status_code=409,
                            )
