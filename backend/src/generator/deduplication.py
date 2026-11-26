"""Deterministic exact/normalized prompt deduplication (v1) for G11.3B.

Normalization scope (bounded and deterministic):
- Unicode NFKC normalization (canonicalizes composed/decomposed forms and compatibility spaces).
- Leading/trailing whitespace trimming.
- Collapsing internal whitespace runs to a single ASCII space.

Important limitation:
This is exact/normalized text deduplication only. It does NOT claim semantic
deduplication or semantic diversity measurement (evaluated separately in G11.5).
"""

from __future__ import annotations

from hashlib import sha256
import re
from typing import Literal, Sequence
import unicodedata

from pydantic import Field

from generator.constants import AsiCode
from generator.models import GeneratedCandidateDraft, StrictGeneratorModel

DEDUPLICATION_METHOD_V1: Literal["exact_normalized_text_v1"] = "exact_normalized_text_v1"

_WHITESPACE_RUN_RE = re.compile(r"\s+")


def normalize_prompt_for_dedup(prompt: str) -> str:
    """Return bounded, deterministic normalized prompt text for exact/normalized dedup."""
    if not isinstance(prompt, str):
        raise ValueError("prompt must be a string.")
    nfkc = unicodedata.normalize("NFKC", prompt)
    return _WHITESPACE_RUN_RE.sub(" ", nfkc.strip())


def compute_prompt_sha256(prompt: str) -> str:
    """Compute exact UTF-8 SHA-256 hash of a candidate prompt."""
    return sha256(prompt.encode("utf-8")).hexdigest()


def compute_normalized_prompt_sha256(prompt: str) -> str:
    """Compute deterministic SHA-256 hash of the normalized candidate prompt."""
    return sha256(normalize_prompt_for_dedup(prompt).encode("utf-8")).hexdigest()


class IndexedCandidateDraft(StrictGeneratorModel):
    """A schema-valid and context-validated candidate paired with its original source index."""

    source_index: int = Field(ge=0, strict=True)
    asi_code: AsiCode
    draft: GeneratedCandidateDraft
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class DuplicateRejection(StrictGeneratorModel):
    """Structured rejection record for a duplicate prompt candidate."""

    source_index: int = Field(ge=0, strict=True)
    asi_code: AsiCode
    reason_code: Literal["duplicate_within_asi", "duplicate_across_asi"]
    reason_message: str = Field(min_length=1, max_length=512)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    duplicate_of_asi_code: AsiCode
    duplicate_of_source_index: int = Field(ge=0, strict=True)
    duplicate_of_candidate_id: str | None = None


class CrossAsiDuplicateReference(StrictGeneratorModel):
    """Kept reference in a cross-ASI deduplication index (never merges or mutates taxonomy)."""

    asi_code: AsiCode
    source_index: int = Field(ge=0, strict=True)
    candidate_id: str | None = None


class DeduplicationOutcome(StrictGeneratorModel):
    """Deterministic within-ASI and optional cross-ASI deduplication summary."""

    method: Literal["exact_normalized_text_v1"] = DEDUPLICATION_METHOD_V1
    pre_dedup_count: int = Field(ge=0, strict=True)
    post_dedup_count: int = Field(ge=0, strict=True)
    within_asi_duplicates_removed: int = Field(ge=0, strict=True)
    across_asi_duplicates_removed: int = Field(ge=0, strict=True)
    kept: tuple[IndexedCandidateDraft, ...] = ()
    rejected: tuple[DuplicateRejection, ...] = ()


def deduplicate_asi_candidates(
    candidates: Sequence[IndexedCandidateDraft],
    *,
    asi_code: AsiCode,
    cross_asi_seen: dict[str, CrossAsiDuplicateReference] | None = None,
    deduplicate_across_asi: bool = True,
) -> DeduplicationOutcome:
    """Deduplicate validated candidates in stable input order without mutating taxonomy.

    - Within the same ASI: always keeps the first candidate and rejects later duplicates
      with `duplicate_within_asi`.
    - Across ASIs: when `deduplicate_across_asi=True` and `cross_asi_seen` is provided,
      rejects candidates whose normalized prompt already appeared in an earlier ASI with
      `duplicate_across_asi` while referencing the earlier ASI/candidate (never merging or
      overwriting taxonomy). When `deduplicate_across_asi=False`, preserves each ASI's
      taxonomy independently.
    """
    within_seen: dict[str, IndexedCandidateDraft] = {}
    kept: list[IndexedCandidateDraft] = []
    rejected: list[DuplicateRejection] = []
    within_removed = 0
    across_removed = 0

    for item in candidates:
        norm_hash = item.normalized_prompt_sha256

        if norm_hash in within_seen:
            first = within_seen[norm_hash]
            within_removed += 1
            rejected.append(
                DuplicateRejection(
                    source_index=item.source_index,
                    asi_code=asi_code,
                    reason_code="duplicate_within_asi",
                    reason_message=(
                        f"Duplicate normalized prompt within {asi_code} "
                        f"(matches earlier candidate at source index {first.source_index})."
                    ),
                    prompt_sha256=item.prompt_sha256,
                    normalized_prompt_sha256=norm_hash,
                    duplicate_of_asi_code=asi_code,
                    duplicate_of_source_index=first.source_index,
                )
            )
            continue

        if deduplicate_across_asi and cross_asi_seen is not None and norm_hash in cross_asi_seen:
            prior = cross_asi_seen[norm_hash]
            across_removed += 1
            rejected.append(
                DuplicateRejection(
                    source_index=item.source_index,
                    asi_code=asi_code,
                    reason_code="duplicate_across_asi",
                    reason_message=(
                        f"Duplicate normalized prompt already accepted under {prior.asi_code}; "
                        f"rejected for {asi_code} to preserve distinct per-ASI taxonomy."
                    ),
                    prompt_sha256=item.prompt_sha256,
                    normalized_prompt_sha256=norm_hash,
                    duplicate_of_asi_code=prior.asi_code,
                    duplicate_of_source_index=prior.source_index,
                    duplicate_of_candidate_id=prior.candidate_id,
                )
            )
            continue

        within_seen[norm_hash] = item
        kept.append(item)

    return DeduplicationOutcome(
        pre_dedup_count=len(candidates),
        post_dedup_count=len(kept),
        within_asi_duplicates_removed=within_removed,
        across_asi_duplicates_removed=across_removed,
        kept=tuple(kept),
        rejected=tuple(rejected),
    )
