"""Versioned historical projections, deliberately independent of evaluator models."""
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, model_validator

SHA256 = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Text = Annotated[str, StringConstraints(max_length=4096)]
HistoricalStatus = Literal["PASS", "FAIL", "INCONCLUSIVE", "ERROR"]
SecurityVerdict = Literal["PASS", "FAIL", "INCONCLUSIVE"]
Scalar = str | bool | int | float | None


class ReportKind(str, Enum):
    EXECUTION = "execution"
    ARCHIVED_ASSESSMENT = "archived_assessment"
    EXTERNAL_BENCHMARK = "external_benchmark"  # Reserved; no model/importer yet.


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class SourceReport(Model):
    format: Literal["native_legacy", "native_partial", "archived_crosscheck_v1"]
    identity: Identifier
    file_byte_sha256: SHA256
    reported_provenance: Literal["synthetic_mock"] | None = None
    normalizer_version: Literal["2B.1.0"] = "2B.1.0"
    byte_hash_computed: Literal[True] = True
    archive_verification: Literal["not_performed"] = "not_performed"
    signature_verification: Literal["not_performed"] = "not_performed"


class Identity(Model):
    testcase_id: Identifier | None = None
    target_id: Identifier | None = None
    target_label: Text | None = None
    adapter: Identifier | None = None
    protocol: Literal["openai_chat_http", "mcp_jsonrpc_http", "unknown"] = "unknown"
    category: Identifier | None = None
    asi_category: Literal["ASI01", "ASI02", "ASI03", "ASI05"] | None = None
    taxonomy_basis: Literal["source_claim", "category_mapping", "unknown"] = "unknown"


class ExecutionState(Model):
    status: Literal["succeeded", "failed", "skipped", "not_started", "unknown"] = "unknown"
    planned: bool | None = None
    attempted: bool | None = None
    confirmed_target_invocation: bool | None = None
    reported_success: bool | None = None
    reported_response_complete: bool | None = None
    status_basis: Literal["source_claim", "unavailable"] = "unavailable"
    http_status: Annotated[int, Field(ge=100, le=599)] | None = None
    duration_ms: Annotated[float, Field(ge=0)] | None = None
    started_at: Text | None = None
    ended_at: Text | None = None
    normalizer_invocation_verification: Literal["not_performed"] = "not_performed"


class HistoricalResult(Model):
    status: HistoricalStatus | None = None
    reason: Text | None = None
    evidence_preview: Text | None = None
    matched_rule_id: Identifier | None = None
    matched_rule_type: Identifier | None = None
    reported_passed: bool | None = None


class DeterministicResult(Model):
    original: HistoricalResult | None = None
    baseline: HistoricalResult | None = None
    effective: HistoricalResult | None = None


class HistoricalSecurity(Model):
    historical_status: HistoricalStatus | None = None
    verdict: SecurityVerdict | None = None
    decisiveness: Literal["decisive", "inconclusive", "technical_error", "unknown"] = "unknown"
    reason: Text | None = None
    sufficiency_review: Literal["not_performed"] = "not_performed"
    policy_re_evaluated: Literal[False] = False

    @model_validator(mode="after")
    def preserve_history(self):
        if self.verdict is not None and self.verdict != self.historical_status:
            raise ValueError("Normalized security verdict must preserve historical status.")
        if self.decisiveness == "decisive" and self.verdict not in {"PASS", "FAIL"}:
            raise ValueError("Decisive security needs a historical PASS or FAIL.")
        if self.decisiveness == "inconclusive" and self.verdict != "INCONCLUSIVE":
            raise ValueError("Inconclusive decisiveness needs the matching historical verdict.")
        return self


class Verification(Model):
    reported_status: Text | None = None
    reported_execution_verified: bool | None = None
    performed_by_normalizer: Literal[False] = False
    normalizer_status: Literal["not_performed"] = "not_performed"
    independent_reverification: Literal["not_repeated"] = "not_repeated"


class Completeness(Model):
    state: Literal["complete", "partial", "unknown"] = "unknown"
    reported_value: bool | None = None
    source_field_present: bool = False
    reported_scopes: list[dict[str, Scalar]] = Field(default_factory=list)
    verification: Verification = Field(default_factory=Verification)


class ReportedEvidence(Model):
    id: Identifier
    kind: Identifier
    reported_source: Identifier
    reported_provenance: Text | None = None
    name: Text | None = None
    source_reference: Text | None = None
    reported_success: bool | None = None
    details: dict[str, Scalar] = Field(default_factory=dict)
    verification: Verification = Field(default_factory=Verification)


class Observation(Model):
    response_preview: Text | None = None
    preview_truncated: bool = False
    preview_redacted: bool = False
    representation: Literal["sanitized_preview_only"] = "sanitized_preview_only"
    response_completeness: Completeness = Field(default_factory=Completeness)
    evidence: list[ReportedEvidence] = Field(default_factory=list)


class Context(Model):
    legitimate_goal: Text | None = None
    attacker_goal: Text | None = None
    attack_entry_point: Text | None = None
    trust_boundary: Text | None = None
    origin: Literal["source_report_claim", "unavailable"] = "unavailable"


class Citation(Model):
    type: Literal["response_span", "runtime_reference"]
    value_preview: Text
    representation: Literal["sanitized_source_citation"] = "sanitized_source_citation"
    revalidated_by_normalizer: Literal[False] = False


class Judge(Model):
    mode: Literal["production_fallback", "archived_research"]
    invocation_state: Literal["not_requested", "skipped_decisive", "prevented", "attempted_failed", "result_available", "unknown"] = "unknown"
    reason: Text | None = None
    reported_semantic_invoked: bool | None = None
    reported_provider_invoked: bool | None = None
    provider_completion_confirmed_by_normalizer: Literal[False] = False
    provider: Text | None = None
    model: Text | None = None
    classification: Text | None = None
    recommendation: HistoricalStatus | None = None
    explanation: Text | None = None
    reported_confidence: Annotated[float, Field(ge=0, le=1)] | None = None
    confidence_calibrated: Literal[False] = False
    reported_json_validation_status: Text | None = None
    validation_repeated_by_normalizer: Literal[False] = False
    provider_fault_code: Text | None = None
    provider_exit_code: int | None = None
    provider_duration_ms: Annotated[float, Field(ge=0)] | None = None
    request_canonical_sha256: SHA256 | None = None
    skill_version: Text | None = None
    skill_sha256: SHA256 | None = None
    downgrade_reason: Text | None = None
    citations: list[Citation] = Field(default_factory=list)


class Comparison(Model):
    state: Literal["not_requested", "skipped_decisive", "prevented", "attempted_failed", "valid_not_comparable", "comparable_agreement", "comparable_disagreement", "comparable_not_recorded", "unknown"] = "unknown"
    reported_status: Literal["agreement", "disagreement", "unavailable"] | None = None
    basis: Literal["source_reported", "not_recorded"] = "not_recorded"
    reason: Text | None = None
    source_inconsistent: bool = False
    verdict_overridden: Literal[False] = False


class TechnicalError(Model):
    stage: Literal["execution", "evaluation", "judge", "report", "unknown"]
    code: Identifier
    safe_message: Text | None = None
    origin: Literal["source_report_claim"] = "source_report_claim"


class HumanReference(Model):
    status: Literal["unavailable", "provisional", "human_verified"] = "unavailable"
    label: Text | None = None
    reviewer_ref: Text | None = None
    verification_basis: Text | None = None
    claim_repeated_by_normalizer: Literal[False] = False

    @model_validator(mode="after")
    def verified_reference_needs_basis(self):
        if self.status == "human_verified" and not (self.label and self.reviewer_ref and self.verification_basis):
            raise ValueError("Human-verified reference needs label, reviewer and basis.")
        return self


class ToolActionExtension(Model):
    declared_name: Text | None = None
    observed_name: Text | None = None
    authorization_ref: Text | None = None
    agent_origin: Literal["reported", "unknown"] = "unknown"


class IdentityAccessExtension(Model):
    actor_ref: Text | None = None
    effective_principal_ref: Text | None = None
    resource_ref: Text | None = None
    baseline_ref: Text | None = None


class CodeExecutionExtension(Model):
    sandbox_ref: Text | None = None
    command_sha256: SHA256 | None = None
    process_event_ref: Text | None = None
    canary_effect_ref: Text | None = None


class CategoryExtensions(Model):
    tool_action: ToolActionExtension | None = None
    identity_access: IdentityAccessExtension | None = None
    code_execution: CodeExecutionExtension | None = None


class HistoricalIntegrityClaims(Model):
    """Recorded digests only: no artifact lookup or archive verification."""
    inventory_file_byte_sha256: SHA256 | None = None
    testcase_file_byte_sha256: SHA256 | None = None
    collector_manifest_file_byte_sha256: SHA256 | None = None
    collector_events_file_byte_sha256: SHA256 | None = None
    collector_log_canonical_json_sha256: SHA256 | None = None
    collector_serialization: Text | None = None
    independent_reverification: Literal["not_repeated"] = "not_repeated"


VerificationState = Literal["verified", "mismatch", "missing", "unsupported", "not_performed"]


class ArtifactCheck(Model):
    artifact_role: Literal["inventory", "manifest", "events", "collector_export", "execution", "assessment"]
    state: VerificationState
    expected_file_byte_sha256: SHA256 | None = None
    actual_file_byte_sha256: SHA256 | None = None
    size_bytes: int | None = Field(default=None, ge=0)


class ArchiveVerification(Model):
    verifier_version: Literal["2B.2.0"] = "2B.2.0"
    file_integrity: VerificationState = "not_performed"
    internal_evidence_consistency: VerificationState = "not_performed"
    collector_canonical_digest: VerificationState = "not_performed"
    crosscheck_linkage: VerificationState = "not_performed"
    external_action_attestation: Literal["not_performed"] = "not_performed"
    artifacts: list[ArtifactCheck] = Field(default_factory=list)
    checks: dict[str, VerificationState] = Field(default_factory=dict)
    fixture_correlation_ref: Text | None = None
    receipt_count: int | None = Field(default=None, ge=0)
    observed_methods: list[Literal["GET", "POST"]] = Field(default_factory=list)
    computed_collector_canonical_sha256: SHA256 | None = None
    # Fixed messages only; never propagate raw paths, URLs, canaries or parse errors.
    limitations: list[Text] = Field(default_factory=lambda: [
        "Local file integrity and stored-record consistency only; no historical request was newly observed.",
        "The unsigned inventory is not an authenticity signature or remote attestation.",
        "Peer-match indicators and timestamps are recorded claims, not independently re-observed network facts.",
        "No security verdict, response completeness or autonomous LLM tool selection is established by verification.",
    ])


class BaseReport(Model):
    report_schema_version: Literal["2.0.0"] = "2.0.0"
    report_id: Identifier
    source: SourceReport
    identity: Identity
    source_reported_at: Text | None = None
    context: Context = Field(default_factory=Context)
    observation: Observation = Field(default_factory=Observation)
    technical_errors: list[TechnicalError] = Field(default_factory=list)
    human_reference: HumanReference = Field(default_factory=HumanReference)
    category_extensions: CategoryExtensions = Field(default_factory=CategoryExtensions)
    historical_integrity: HistoricalIntegrityClaims = Field(default_factory=HistoricalIntegrityClaims)
    artifact_verification: ArchiveVerification | None = None
    limitations: list[Text] = Field(default_factory=list)
    normalization_notes: list[Text] = Field(default_factory=list)


class ExecutionReport(BaseReport):
    report_kind: Literal["execution"] = "execution"
    execution_id: Identifier | None = None
    record_status: Literal["complete", "partial"] = "complete"
    execution: ExecutionState
    reported_wrapper_execution_success: bool | None = None
    original_execution_result: ExecutionState | None = None
    deterministic: DeterministicResult = Field(default_factory=DeterministicResult)
    original_final_result: HistoricalResult | None = None
    security: HistoricalSecurity
    judge: Judge
    comparison: Comparison


class ParentExecution(Model):
    execution_id: Identifier | None = None
    report_file_byte_sha256: SHA256 | None = None
    fixture_correlation_id: Identifier | None = None
    deterministic_verdict: HistoricalStatus | None = None
    original_verdict_snapshot: HistoricalStatus | None = None
    reported_response_complete: bool | None = None
    matched_rule_id: Identifier | None = None
    reference_validation: Literal["not_performed"] = "not_performed"


class ArchivedAssessmentReport(BaseReport):
    report_kind: Literal["archived_assessment"] = "archived_assessment"
    target_execution_performed: Literal[False] = False
    source_execution: ParentExecution
    judge: Judge
    comparison: Comparison
    reported_archive_integrity_unchanged: bool | None = None


EvaluationReport = Annotated[ExecutionReport | ArchivedAssessmentReport, Field(discriminator="report_kind")]
REPORT_ADAPTER = TypeAdapter(EvaluationReport)
