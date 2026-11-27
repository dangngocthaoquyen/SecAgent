"""Strict Pydantic contracts for G11 Generation Skills, limits, and LLM output drafts."""

from __future__ import annotations

import re
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from generator.constants import (
    ASI_CODE_TO_CATEGORY,
    AsiCategory,
    AsiCode,
    CATEGORY_TO_ASI_CODE,
    DEFAULT_MAX_PER_ASI,
    DEFAULT_MAX_TOTAL_CASES,
    DEFAULT_MIN_PER_ASI,
    DEFAULT_PER_ASI,
    GENERATOR_SKILL_ID,
    GENERATOR_SKILL_SCHEMA_VERSION,
    HARD_MAX_PER_ASI,
    HARD_MAX_TOTAL_CASES,
    KNOWN_APPLICATION_CONTEXT_FIELDS,
    MAX_CANDIDATE_PROMPT_UTF8_BYTES,
)

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STRATEGY_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class StrictGeneratorModel(BaseModel):
    """Base contract forbidding unknown or authority-escalating fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class GenerationLimits(StrictGeneratorModel):
    """Centralized generation count limits with locked v1 hard ceilings (<= 50/ASI, <= 50 total)."""

    min_per_asi: int = Field(default=DEFAULT_MIN_PER_ASI, ge=1, le=HARD_MAX_PER_ASI, strict=True)
    default_per_asi: int = Field(default=DEFAULT_PER_ASI, ge=1, le=HARD_MAX_PER_ASI, strict=True)
    max_per_asi: int = Field(default=DEFAULT_MAX_PER_ASI, ge=1, le=HARD_MAX_PER_ASI, strict=True)
    max_total_cases: int = Field(
        default=DEFAULT_MAX_TOTAL_CASES, ge=1, le=HARD_MAX_TOTAL_CASES, strict=True
    )

    @model_validator(mode="after")
    def validate_bounds(self) -> "GenerationLimits":
        if not (self.min_per_asi <= self.default_per_asi <= self.max_per_asi):
            raise ValueError("Generation limits must satisfy min_per_asi <= default_per_asi <= max_per_asi.")
        if self.max_per_asi > self.max_total_cases:
            raise ValueError("max_per_asi cannot exceed max_total_cases.")
        return self

    def validate_per_asi_counts(self, counts_by_asi: Mapping[str, int]) -> dict[AsiCode, int]:
        """Validate per-ASI requested integer counts, reject duplicate aliases, and enforce total ceiling."""
        if not counts_by_asi:
            raise ValueError("At least one ASI category must be requested.")
        normalized: dict[AsiCode, int] = {}
        total = 0
        for raw_key, count in counts_by_asi.items():
            if not isinstance(raw_key, str):
                raise ValueError("ASI key must be a string.")
            code = normalize_asi_code(raw_key)
            if code in normalized:
                raise ValueError(f"Duplicate ASI category {code!r} in generation counts.")
            if isinstance(count, bool) or not isinstance(count, int):
                raise ValueError(f"Requested count for {code} must be an integer.")
            if count < self.min_per_asi or count > self.max_per_asi:
                raise ValueError(
                    f"Requested count for {code} ({count}) must be between "
                    f"{self.min_per_asi} and {self.max_per_asi}."
                )
            normalized[code] = count
            total += count
        if total > self.max_total_cases:
            raise ValueError(
                f"Total requested testcases ({total}) exceeds maximum limit of {self.max_total_cases}."
            )
        return normalized


DEFAULT_GENERATION_LIMITS = GenerationLimits()


def normalize_asi_code(raw: str) -> AsiCode:
    """Resolve an exact allowlisted ASI code or internal category name."""
    if not isinstance(raw, str):
        raise ValueError("ASI identifier must be a string.")
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("ASI identifier must not be empty.")
    upper = cleaned.upper()
    if upper in ASI_CODE_TO_CATEGORY:
        return upper  # type: ignore[return-value]
    lower = cleaned.lower()
    if lower in CATEGORY_TO_ASI_CODE:
        return CATEGORY_TO_ASI_CODE[lower]  # type: ignore[index]
    raise ValueError(f"Unsupported ASI category: {raw!r}.")


class GeneratorSkillIdentity(StrictGeneratorModel):
    """Immutable provenance identity for a loaded G11 Generation Skill bundle."""

    id: Literal["secagent-g11-generator"] = GENERATOR_SKILL_ID
    version: str = Field(min_length=1, max_length=32)
    schema_version: Literal["1.0"] = GENERATOR_SKILL_SCHEMA_VERSION
    asi_code: AsiCode
    asi_category: AsiCategory
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: tuple[str, ...] = Field(min_length=1)

    @field_validator("version")
    @classmethod
    def check_semver(cls, value: str) -> str:
        if not _SEMVER_RE.fullmatch(value):
            raise ValueError("Generation skill version must use semantic versioning (X.Y.Z).")
        return value

    @field_validator("sha256")
    @classmethod
    def check_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("Generation skill sha256 must be a 64-character lowercase hex digest.")
        return value

    @model_validator(mode="after")
    def check_category_alignment(self) -> "GeneratorSkillIdentity":
        expected_category = ASI_CODE_TO_CATEGORY[self.asi_code]
        if self.asi_category != expected_category:
            raise ValueError(
                f"ASI category {self.asi_category!r} does not match {self.asi_code!r} ({expected_category!r})."
            )
        return self


class GeneratorSkillBundle(StrictGeneratorModel):
    """Loaded, integrity-verified Generation Skill bundle ready for a single ASI call."""

    identity: GeneratorSkillIdentity
    system_prompt: str = Field(min_length=1)
    total_bytes: int = Field(gt=0, strict=True)


class GeneratedCandidateDraft(StrictGeneratorModel):
    """Strict untrusted candidate schema returned by an LLM provider.

    - Explicitly forbids testcase IDs, verdicts, assertions, rules, markers,
      runtime evidence, or authorization fields (`extra="forbid"`).
    - `prompt` is bounded to `MAX_CANDIDATE_PROMPT_UTF8_BYTES` (4096 UTF-8 bytes).
    - `context_basis` accepts only canonical allowlisted SecAgent field names
      (`KNOWN_APPLICATION_CONTEXT_FIELDS`); verifying presence in the target's
      confirmed context snapshot is performed in G11.3B.
    - `scope_note` is required descriptive metadata only and MUST NEVER be used
      as trusted execution scope, evaluation policy, or execution authorization.
    """

    prompt: str = Field(min_length=1, max_length=MAX_CANDIDATE_PROMPT_UTF8_BYTES)
    description: str = Field(min_length=1, max_length=512)
    strategy_tag: str = Field(min_length=2, max_length=64)
    context_basis: tuple[str, ...] = Field(min_length=1, max_length=16)
    scope_note: str = Field(min_length=1, max_length=512)

    @field_validator("prompt")
    @classmethod
    def check_prompt_utf8_bounds(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_CANDIDATE_PROMPT_UTF8_BYTES:
            raise ValueError(
                f"Candidate prompt exceeds {MAX_CANDIDATE_PROMPT_UTF8_BYTES} UTF-8 bytes."
            )
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Candidate prompt must not be blank.")
        if len(cleaned.encode("utf-8")) > MAX_CANDIDATE_PROMPT_UTF8_BYTES:
            raise ValueError(
                f"Candidate prompt exceeds {MAX_CANDIDATE_PROMPT_UTF8_BYTES} UTF-8 bytes."
            )
        return cleaned

    @field_validator("description", "scope_note")
    @classmethod
    def require_nonblank_text(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Candidate descriptive field must not be blank.")
        return cleaned

    @field_validator("strategy_tag")
    @classmethod
    def check_strategy_tag(cls, value: str) -> str:
        cleaned = value.strip()
        if not _STRATEGY_TAG_RE.fullmatch(cleaned):
            raise ValueError("strategy_tag must be a lowercase snake_case/kebab-case token.")
        return cleaned

    @field_validator("context_basis")
    @classmethod
    def check_context_basis(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in values:
            token = item.strip()
            if token not in KNOWN_APPLICATION_CONTEXT_FIELDS:
                raise ValueError(
                    f"Unsupported context_basis field {item!r}; must be in KNOWN_APPLICATION_CONTEXT_FIELDS."
                )
            if token not in seen:
                seen.add(token)
                cleaned.append(token)
        if not cleaned:
            raise ValueError("context_basis must contain at least one known context field.")
        return tuple(cleaned)


class RawGenerationOutputContract(StrictGeneratorModel):
    """Top-level strict JSON contract expected from the Generation LLM Provider.

    Contract note (R03E):
    - `candidates == ()` is permitted ONLY when `context_gaps` is non-empty so
      the model can report missing, conflicting, or out-of-scope prerequisites
      instead of fabricating testcases.
    - An empty `candidates` result is NEVER a valid dataset to persist in
      `DatasetRepository` or execute in a Scan; G11.3B/G11.3C handle empty and
      partial generation outcomes explicitly.
    """

    schema_version: Literal["1.0"]
    asi_category: AsiCode
    context_gaps: tuple[str, ...] = Field(default=(), max_length=20)
    candidates: tuple[GeneratedCandidateDraft, ...] = Field(
        default=(), min_length=0, max_length=HARD_MAX_PER_ASI
    )

    @field_validator("context_gaps")
    @classmethod
    def clean_context_gaps(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for item in values:
            text = item.strip()
            if not text:
                raise ValueError("context_gaps entries must not be blank.")
            if len(text) > 512:
                raise ValueError("context_gaps entry exceeds 512 characters.")
            cleaned.append(text)
        return tuple(cleaned)

    @model_validator(mode="after")
    def require_context_gaps_when_empty(self) -> "RawGenerationOutputContract":
        if len(self.candidates) == 0 and len(self.context_gaps) == 0:
            raise ValueError(
                "Empty candidates result must include at least one context_gaps explanation."
            )
        return self
