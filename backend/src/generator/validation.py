"""Deterministic backend validation for parsed LLM generation candidates (G11.3B).

Validates parsed `RawGenerationOutputContract` against backend-owned facts:
- ASI consistency: `contract.asi_category` must exactly match the requested `AsiCode`.
- Confirmed context basis: every field in `candidate.context_basis` must exist in the
  confirmed snapshot AND projected context fields (or a valid, explicitly bound Reviewed
  Policy for `"reviewed_policy"`). Unverified, missing-provenance, or absent fields are
  rejected with structured reason codes.
- Safety & scope separation: effective evaluation scope ALWAYS comes from backend
  Readiness (`assessment.effective_scope`), never from `candidate.scope_note`;
  `strategy_tag` is treated strictly as descriptive metadata.

Does NOT implement arbitrary keyword heuristics claiming semantic safety or quality,
and NEVER probes the Target.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from generator.constants import AsiCode, KNOWN_APPLICATION_CONTEXT_FIELDS
from generator.deduplication import (
    IndexedCandidateDraft,
    compute_normalized_prompt_sha256,
    compute_prompt_sha256,
)
from generator.models import RawGenerationOutputContract, StrictGeneratorModel
from generator.readiness import AsiReadinessAssessment, ConfirmedContextSnapshot
from generator.request_builder import GenerationProvenanceInputs

CandidateValidationRejectionCode = Literal[
    "unsupported_context_basis",
    "unverified_context_basis",
    "missing_provenance_context_basis",
    "missing_context_basis",
    "unconfirmed_reviewed_policy_basis",
]


class ValidationRejection(StrictGeneratorModel):
    """Structured rejection for a single candidate failing backend consistency checks."""

    source_index: int = Field(ge=0, strict=True)
    asi_code: AsiCode
    reason_code: CandidateValidationRejectionCode
    reason_message: str = Field(min_length=1, max_length=512)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invalid_context_fields: tuple[str, ...] = ()


class CandidateValidationOutcome(StrictGeneratorModel):
    """Deterministic validation result for all candidates in one ASI output."""

    asi_code: AsiCode
    asi_matched: bool
    asi_mismatch_message: str | None = None
    valid_candidates: tuple[IndexedCandidateDraft, ...] = ()
    rejected_candidates: tuple[ValidationRejection, ...] = ()


def _classify_context_basis_violation(
    context_basis: tuple[str, ...],
    *,
    asi_code: AsiCode,
    snapshot: ConfirmedContextSnapshot,
    assessment: AsiReadinessAssessment,
    projected_context_fields: frozenset[str],
) -> tuple[CandidateValidationRejectionCode, tuple[str, ...], str] | None:
    """Verify every context_basis token is grounded in the confirmed snapshot / reviewed policy."""
    unsupported: list[str] = []
    unverified: list[str] = []
    missing_prov: list[str] = []
    missing_fields: list[str] = []
    invalid_policy = False

    has_valid_reviewed_policy = (
        assessment.has_reviewed_policy
        and assessment.reviewed_policy_id is not None
        and asi_code in snapshot.reviewed_policies
        and snapshot.reviewed_policies[asi_code].policy_id == assessment.reviewed_policy_id
    )

    excluded_unverified_set = set(snapshot.excluded_unverified_fields)
    excluded_missing_prov_set = set(snapshot.excluded_missing_provenance_fields)

    for token in context_basis:
        if token not in KNOWN_APPLICATION_CONTEXT_FIELDS:
            unsupported.append(token)
            continue

        if token == "reviewed_policy":
            if not has_valid_reviewed_policy:
                invalid_policy = True
            continue

        if token in snapshot.confirmed_fields and token in projected_context_fields:
            continue

        if token in excluded_unverified_set:
            unverified.append(token)
        elif token in excluded_missing_prov_set:
            missing_prov.append(token)
        else:
            missing_fields.append(token)

    if unsupported:
        return (
            "unsupported_context_basis",
            tuple(unsupported),
            "Candidate cites unsupported context_basis field(s): " + ", ".join(unsupported) + ".",
        )
    if invalid_policy:
        return (
            "unconfirmed_reviewed_policy_basis",
            ("reviewed_policy",),
            f"Candidate cites 'reviewed_policy', but no valid reviewed policy is bound for {asi_code}.",
        )
    if unverified:
        return (
            "unverified_context_basis",
            tuple(unverified),
            "Candidate cites unverified/discovery-only context field(s) excluded from snapshot: "
            + ", ".join(unverified)
            + ".",
        )
    if missing_prov:
        return (
            "missing_provenance_context_basis",
            tuple(missing_prov),
            "Candidate cites context field(s) lacking explicit operator_confirmed provenance: "
            + ", ".join(missing_prov)
            + ".",
        )
    if missing_fields:
        return (
            "missing_context_basis",
            tuple(missing_fields),
            "Candidate cites context field(s) absent from the confirmed context snapshot: "
            + ", ".join(missing_fields)
            + ".",
        )
    return None


def validate_parsed_output(
    contract: RawGenerationOutputContract,
    *,
    expected_asi_code: AsiCode,
    snapshot: ConfirmedContextSnapshot,
    assessment: AsiReadinessAssessment,
    provenance_inputs: GenerationProvenanceInputs,
    source_index_offset: int = 0,
) -> CandidateValidationOutcome:
    """Validate ASI consistency and confirmed context_basis grounding for one ASI output."""
    if isinstance(source_index_offset, bool) or not isinstance(source_index_offset, int) or source_index_offset < 0:
        raise ValueError("source_index_offset must be a non-negative integer.")
    if contract.asi_category != expected_asi_code:
        return CandidateValidationOutcome(
            asi_code=expected_asi_code,
            asi_matched=False,
            asi_mismatch_message=(
                f"LLM output declared asi_category '{contract.asi_category}', "
                f"which does not match backend-requested '{expected_asi_code}'."
            ),
        )

    projected_fields = frozenset(provenance_inputs.projected_context_fields)
    valid: list[IndexedCandidateDraft] = []
    rejected: list[ValidationRejection] = []

    for idx, draft in enumerate(contract.candidates):
        global_idx = source_index_offset + idx
        prompt_hash = compute_prompt_sha256(draft.prompt)
        norm_hash = compute_normalized_prompt_sha256(draft.prompt)
        violation = _classify_context_basis_violation(
            draft.context_basis,
            asi_code=expected_asi_code,
            snapshot=snapshot,
            assessment=assessment,
            projected_context_fields=projected_fields,
        )
        if violation is not None:
            reason_code, invalid_fields, reason_message = violation
            rejected.append(
                ValidationRejection(
                    source_index=global_idx,
                    asi_code=expected_asi_code,
                    reason_code=reason_code,
                    reason_message=reason_message,
                    prompt_sha256=prompt_hash,
                    normalized_prompt_sha256=norm_hash,
                    invalid_context_fields=invalid_fields,
                )
            )
            continue

        valid.append(
            IndexedCandidateDraft(
                source_index=global_idx,
                asi_code=expected_asi_code,
                draft=draft,
                prompt_sha256=prompt_hash,
                normalized_prompt_sha256=norm_hash,
            )
        )

    return CandidateValidationOutcome(
        asi_code=expected_asi_code,
        asi_matched=True,
        valid_candidates=tuple(valid),
        rejected_candidates=tuple(rejected),
    )
