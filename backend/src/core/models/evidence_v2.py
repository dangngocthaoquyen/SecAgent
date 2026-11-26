"""Strict typed models for SecAgent Evidence Contract v2.

Evidence Contract v2 provides a versioned, fail-closed, security-bounded
representation of observed agent behavior across response, tool-intent,
execution, and observation-coverage dimensions.

Design invariants:
- Evidence Contract v2 NEVER decides PASS / FAIL / INCONCLUSIVE verdicts.
- Agent speech (response observation) NEVER proves execution.
- Tool intent / dispatched requests NEVER prove execution success.
- Execution verification requires independent provenance and valid correlation;
  forged or cross-run metadata fails closed.
- Missing or partial traces NEVER establish verified absence of action.
- Historical v1 projections are explicitly marked and NEVER claim newly
  verified execution.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

EVIDENCE_CONTRACT_V2_VERSION: Literal["2.0"] = "2.0"

# Exact mirror of evaluators.contract scope taxonomy (do not expand taxonomy).
RESPONSE_ONLY_SCOPES: frozenset[str] = frozenset({
    "goal_hijack_response",
    "tool_intent_response",
    "identity_claim_response",
    "response_command_artifact",
})

EXECUTION_SCOPES: frozenset[str] = frozenset({
    "execution_action",
    "agent_run",
    "direct_request",
    "web_fetch",
    "web_callback",
})

SUPPORTED_EVALUATION_SCOPES: frozenset[str] = RESPONSE_ONLY_SCOPES | EXECUTION_SCOPES

MAX_OBSERVATION_RECORDS = 128
MAX_REASON_CODES = 64
MAX_CONTRADICTIONS = 32
MAX_MISSING_INDICATORS = 32
MAX_EVIDENCE_REFERENCES = 128
MAX_UNOBSERVED_SURFACES = 16
MAX_LIMITATIONS = 32
MAX_TEXT_PREVIEW = 1024
MAX_RESPONSE_CHARS = 10_000_000
MAX_INPUT_DEPTH = 6

SHA256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
BoundedId = Annotated[str, StringConstraints(min_length=1, max_length=256)]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=512)]
PreviewText = Annotated[str, StringConstraints(max_length=MAX_TEXT_PREVIEW)]

TrustClassification = Literal[
    "model_reported",
    "target_reported",
    "adapter_observed",
    "independently_verified",
]

HighestTrustClassification = Literal[
    "none",
    "model_reported",
    "target_reported",
    "adapter_observed",
    "independently_verified",
]

ResponseCompleteness = Literal["complete", "partial", "unknown", "missing"]

CoverageState = Literal[
    "complete",
    "partial",
    "unknown",
    "missing",
    "contradicted",
    "verified_absence",
]

RefusalState = Literal[
    "refusal_observed",
    "refusal_not_established",
    "not_applicable",
]

ActionPresenceState = Literal[
    "action_observed",
    "no_action_within_complete_coverage",
    "coverage_incomplete_or_unknown",
]

ToolIntentOrigin = Literal[
    "model_emitted_text",
    "declared_tool_call",
    "adapter_observed_request",
    "mcp_request_dispatched",
    "rejected_tool_call",
]

ExecutionObservationKind = Literal[
    "real_runtime_effect",
    "simulated_handler_effect",
    "verified_attempted_failed",
    "target_reported_result",
    "unverified_execution_claim",
]

ExecutionVerificationStatus = Literal[
    "verified_runtime_effect",
    "verified_attempted_failed",
    "verified_simulated_effect",
    "unverified_claim",
    "contradicted",
    "none",
]

CorrelationStrengthV2 = Literal["strong", "weak", "none", "unknown"]

ScopeFamily = Literal["response_only", "execution", "unknown", "unsupported"]

ScopeAlignmentStatus = Literal[
    "compatible",
    "insufficient_evidence_for_scope",
    "scope_mismatch",
    "scope_unknown",
]

ProjectionOrigin = Literal["live_observation", "historical_v1_projection"]

FindingCategory = Literal[
    "contradiction",
    "missing",
    "correlation",
    "trust_escalation_blocked",
    "scope_gap",
]


class EvidenceV2Model(BaseModel):
    """Strict, frozen, closed base model for all Evidence Contract v2 records."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        allow_inf_nan=False,
    )


class CorrelationContextV2(EvidenceV2Model):
    """Trusted run/execution correlation identifiers supplied by SecAgent."""

    secagent_run_id: BoundedId | None = None
    secagent_execution_id: BoundedId | None = None
    secagent_testcase_id: BoundedId | None = None
    secagent_target_id: BoundedId | None = None
    target_correlation_id: BoundedId | None = None
    request_id: BoundedId | None = None
    session_id: BoundedId | None = None


class ResponseObservationV2(EvidenceV2Model):
    """Response-level facts observed from agent text output (never execution proof)."""

    observed: bool
    completeness: ResponseCompleteness
    response_sha256: SHA256 | None = None
    response_char_count: Annotated[int, Field(ge=0, le=MAX_RESPONSE_CHARS)] = 0
    response_preview: PreviewText | None = None
    explicit_refusal: RefusalState = "not_applicable"
    identity_claim_present: bool = False
    command_suggestion_present: bool = False
    textual_tool_claim_present: bool = False
    trust_classification: Literal["target_reported", "model_reported"] = "target_reported"
    proves_execution: Literal[False] = False

    @model_validator(mode="after")
    def check_response_consistency(self) -> "ResponseObservationV2":
        if self.observed and self.response_sha256 is None:
            raise ValueError("Observed response must carry a deterministic response_sha256.")
        if not self.observed and self.response_preview is not None:
            raise ValueError("Unobserved response cannot include a response_preview.")
        return self


class ToolIntentRecordV2(EvidenceV2Model):
    """Observed tool intent or dispatched tool request (never execution success)."""

    record_id: BoundedId
    kind: BoundedId
    source: BoundedId
    tool_name: BoundedId | None = None
    arguments_sha256: SHA256 | None = None
    correlation_reference: BoundedId | None = None
    intent_origin: ToolIntentOrigin
    trust_classification: TrustClassification
    proves_execution_success: Literal[False] = False
    evidence_sha256: SHA256


class ExecutionObservationRecordV2(EvidenceV2Model):
    """Execution or side-effect observation with explicit trust and correlation status."""

    record_id: BoundedId
    kind: BoundedId
    source: BoundedId
    action_name: BoundedId | None = None
    trust_classification: TrustClassification
    execution_kind: ExecutionObservationKind
    execution_verified: bool
    is_synthetic: bool = False
    action_succeeded: bool | None = None
    correlation_verified: bool = False
    correlation_strength: CorrelationStrengthV2 = "unknown"
    correlation_status: BoundedId = "unknown"
    arguments_sha256: SHA256 | None = None
    effect_sha256: SHA256 | None = None
    reference: BoundedId | None = None
    evidence_sha256: SHA256
    contradictions: list[BoundedText] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def check_execution_invariants(self) -> "ExecutionObservationRecordV2":
        if self.execution_verified:
            if self.trust_classification != "independently_verified":
                raise ValueError("Verified execution requires independently_verified trust.")
            if not self.correlation_verified:
                raise ValueError("Verified execution requires verified correlation.")
            if self.execution_kind in {"target_reported_result", "unverified_execution_claim"}:
                raise ValueError("Unverified execution_kind cannot set execution_verified=True.")
        else:
            if self.execution_kind in {
                "real_runtime_effect",
                "simulated_handler_effect",
                "verified_attempted_failed",
            }:
                raise ValueError("Unverified record cannot claim verified execution_kind.")
        if self.execution_kind == "simulated_handler_effect" and not self.is_synthetic:
            raise ValueError("simulated_handler_effect must set is_synthetic=True.")
        if self.execution_kind == "real_runtime_effect" and self.is_synthetic:
            raise ValueError("real_runtime_effect cannot set is_synthetic=True.")
        if self.execution_kind == "verified_attempted_failed" and self.action_succeeded is True:
            raise ValueError("verified_attempted_failed cannot claim action_succeeded=True.")
        return self


class ObservationCoverageV2(EvidenceV2Model):
    """Explicit representation of observation completeness, refusal, and action presence."""

    response_completeness: ResponseCompleteness
    action_trace_completeness: CoverageState
    request_trace_completeness: ResponseCompleteness = "missing"
    action_presence: ActionPresenceState
    refusal_state: RefusalState
    unobserved_surfaces: list[BoundedId] = Field(
        default_factory=list,
        max_length=MAX_UNOBSERVED_SURFACES,
    )
    verified_absence_boundary: BoundedText | None = None

    @model_validator(mode="after")
    def check_absence_invariants(self) -> "ObservationCoverageV2":
        if self.action_presence == "no_action_within_complete_coverage":
            if self.action_trace_completeness != "verified_absence":
                raise ValueError(
                    "no_action_within_complete_coverage requires action_trace_completeness='verified_absence'."
                )
            if not self.verified_absence_boundary:
                raise ValueError(
                    "Verified absence requires an explicit verified_absence_boundary."
                )
        elif self.action_trace_completeness == "verified_absence":
            raise ValueError(
                "action_trace_completeness='verified_absence' requires action_presence='no_action_within_complete_coverage'."
            )
        return self


class EvidenceFindingV2(EvidenceV2Model):
    """Structured missing-evidence, correlation, or contradiction indicator."""

    code: BoundedId
    category: FindingCategory
    message: BoundedText
    record_ids: list[BoundedId] = Field(default_factory=list, max_length=16)


class ScopeAlignmentV2(EvidenceV2Model):
    """Compatibility of observed evidence with the backend-confirmed evaluation scope."""

    effective_scope: BoundedId | None = None
    scope_family: ScopeFamily
    alignment_status: ScopeAlignmentStatus
    requires_execution_evidence: bool
    response_evidence_sufficient_for_scope: bool
    execution_evidence_sufficient_for_scope: bool
    reason_codes: list[BoundedId] = Field(default_factory=list, max_length=MAX_REASON_CODES)
    limitations: list[BoundedText] = Field(default_factory=list, max_length=MAX_LIMITATIONS)


class EvidenceContractV2(EvidenceV2Model):
    """Versioned, fail-closed Evidence Contract v2 envelope."""

    contract_version: Literal["2.0"] = EVIDENCE_CONTRACT_V2_VERSION
    projection_origin: ProjectionOrigin = "live_observation"
    correlation: CorrelationContextV2 = Field(default_factory=CorrelationContextV2)
    effective_evaluation_scope: BoundedId | None = None
    scope_alignment: ScopeAlignmentV2
    response_observation: ResponseObservationV2
    tool_intents: list[ToolIntentRecordV2] = Field(
        default_factory=list,
        max_length=MAX_OBSERVATION_RECORDS,
    )
    execution_observations: list[ExecutionObservationRecordV2] = Field(
        default_factory=list,
        max_length=MAX_OBSERVATION_RECORDS,
    )
    coverage: ObservationCoverageV2
    highest_trust_classification: HighestTrustClassification
    trust_classifications_present: list[TrustClassification] = Field(
        default_factory=list,
        max_length=4,
    )
    verified_execution_status: ExecutionVerificationStatus
    verified_execution_present: bool
    synthetic_execution_present: bool = False
    missing_evidence_indicators: list[EvidenceFindingV2] = Field(
        default_factory=list,
        max_length=MAX_MISSING_INDICATORS,
    )
    contradictions: list[EvidenceFindingV2] = Field(
        default_factory=list,
        max_length=MAX_CONTRADICTIONS,
    )
    evidence_references: list[BoundedId] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_REFERENCES,
    )
    envelope_sha256: SHA256
    limitations: list[BoundedText] = Field(default_factory=list, max_length=MAX_LIMITATIONS)
    reason_codes: list[BoundedId] = Field(default_factory=list, max_length=MAX_REASON_CODES)

    @model_validator(mode="after")
    def check_envelope_invariants(self) -> "EvidenceContractV2":
        verified_records = [
            rec for rec in self.execution_observations if rec.execution_verified
        ]
        if self.verified_execution_present:
            if self.projection_origin == "historical_v1_projection":
                raise ValueError(
                    "Historical v1 projections cannot claim newly verified execution."
                )
            if self.highest_trust_classification != "independently_verified":
                raise ValueError(
                    "verified_execution_present requires highest_trust_classification='independently_verified'."
                )
            if self.verified_execution_status not in {
                "verified_runtime_effect",
                "verified_attempted_failed",
                "verified_simulated_effect",
            }:
                raise ValueError(
                    "verified_execution_present disagrees with verified_execution_status."
                )
            if not verified_records:
                raise ValueError(
                    "verified_execution_present requires at least one verified execution record."
                )
        else:
            if self.verified_execution_status in {
                "verified_runtime_effect",
                "verified_attempted_failed",
                "verified_simulated_effect",
            }:
                raise ValueError(
                    "Unverified envelope cannot report a verified_execution_status."
                )
            if verified_records:
                raise ValueError(
                    "Envelope with verified execution records must set verified_execution_present=True."
                )

        if self.projection_origin == "historical_v1_projection":
            if self.highest_trust_classification == "independently_verified":
                raise ValueError(
                    "Historical v1 projections cannot assert independently_verified trust."
                )

        if self.coverage.action_presence == "no_action_within_complete_coverage":
            if self.execution_observations or self.tool_intents:
                raise ValueError(
                    "Verified absence cannot coexist with observed tool intents or execution records."
                )

        if self.coverage.response_completeness != self.response_observation.completeness:
            raise ValueError(
                "coverage.response_completeness must match response_observation.completeness."
            )
        if self.coverage.refusal_state != self.response_observation.explicit_refusal:
            raise ValueError(
                "coverage.refusal_state must match response_observation.explicit_refusal."
            )

        if self.effective_evaluation_scope != self.scope_alignment.effective_scope:
            raise ValueError(
                "effective_evaluation_scope must match scope_alignment.effective_scope."
            )

        return self


__all__ = [
    "EVIDENCE_CONTRACT_V2_VERSION",
    "RESPONSE_ONLY_SCOPES",
    "EXECUTION_SCOPES",
    "SUPPORTED_EVALUATION_SCOPES",
    "MAX_OBSERVATION_RECORDS",
    "MAX_REASON_CODES",
    "MAX_CONTRADICTIONS",
    "MAX_MISSING_INDICATORS",
    "MAX_EVIDENCE_REFERENCES",
    "MAX_UNOBSERVED_SURFACES",
    "MAX_LIMITATIONS",
    "MAX_TEXT_PREVIEW",
    "MAX_RESPONSE_CHARS",
    "MAX_INPUT_DEPTH",
    "TrustClassification",
    "HighestTrustClassification",
    "ResponseCompleteness",
    "CoverageState",
    "RefusalState",
    "ActionPresenceState",
    "ToolIntentOrigin",
    "ExecutionObservationKind",
    "ExecutionVerificationStatus",
    "CorrelationStrengthV2",
    "ScopeFamily",
    "ScopeAlignmentStatus",
    "ProjectionOrigin",
    "FindingCategory",
    "CorrelationContextV2",
    "ResponseObservationV2",
    "ToolIntentRecordV2",
    "ExecutionObservationRecordV2",
    "ObservationCoverageV2",
    "EvidenceFindingV2",
    "ScopeAlignmentV2",
    "EvidenceContractV2",
]
