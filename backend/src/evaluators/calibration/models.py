"""Strict Pydantic v2 contracts for G12 Phase 5 Judge Accuracy & Calibration."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.models import Observation, TestCase
from core.models.evidence_v2 import EvidenceContractV2

AsiGroup = Literal["ASI01", "ASI02", "ASI03", "ASI05"]
CategoryName = Literal[
    "goal_hijacking",
    "tool_misuse",
    "identity_privilege_abuse",
    "unexpected_code_execution",
]
BenchmarkSourceLabel = Literal[
    "synthetic",
    "controlled_fixture",
    "verified_target_evidence",
]
BenchmarkSplit = Literal["calibration", "holdout"]
ScopeFamilyLabel = Literal["response_only", "execution", "mismatched"]
ExpectedVerdictLabel = Literal["PASS", "FAIL", "INCONCLUSIVE"]
ActualVerdictLabel = Literal["PASS", "FAIL", "INCONCLUSIVE", "ERROR"]

EvidenceScenarioType = Literal[
    "successful_attack",
    "safe_refusal",
    "benign_authorized_behavior",
    "refusal_with_actual_violation",
    "verified_prohibited_execution",
    "verified_benign_execution",
    "tool_intent_without_execution_proof",
    "target_reported_execution_claim",
    "simulated_execution",
    "complete_verified_absence",
    "partial_or_missing_trace",
    "contradictory_evidence",
    "scope_mismatch",
    "cross_run_correlation_mismatch",
    "ambiguous_semantic_response",
    "policy_or_context_mismatch",
    "credential_disclosure_or_unauth_data",
]

FailureCauseCategory = Literal[
    "semantic_misunderstanding",
    "policy_interpretation",
    "incorrect_context_grounding",
    "evidence_insufficiency",
    "false_execution_inference",
    "incomplete_trace",
    "verdict_resolver_downgrade",
    "provider_error",
    "benchmark_label_ambiguity",
]

EvaluationPipelineMode = Literal[
    "deterministic_baseline",
    "phase4_evidence_aware",
    "llm_judge_skills_v2",
]

ExecutionOriginLabel = Literal[
    "offline_deterministic",
    "offline_simulated_judge",
    "live_deepseek_pilot",
]

DecisionAuthorityLabel = Literal[
    "deterministic_rule",
    "evidence_v2_gate",
    "asi05_execution",
    "llm_judge",
    "verdict_resolver_guard",
    "provider_fault",
]


class BenchmarkCase(BaseModel):
    """One reproducible, independently labeled benchmark case for Judge calibration."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=3, max_length=64)
    asi: AsiGroup
    category: CategoryName
    split: BenchmarkSplit
    scenario_type: EvidenceScenarioType
    target_context: dict[str, Any] = Field(default_factory=dict)
    evaluation_scope: str = Field(min_length=1, max_length=128)
    scope_family: ScopeFamilyLabel
    reviewed_policy: dict[str, Any] = Field(default_factory=dict)
    testcase: TestCase
    observation: Observation
    evidence_v2: EvidenceContractV2
    expected_verdict: ExpectedVerdictLabel
    ground_truth_determinate: bool = Field(strict=True)
    expected_reasoning_category: str = Field(min_length=1, max_length=128)
    expected_evidence_requirements: list[str] = Field(min_length=1)
    ground_truth_rationale: str = Field(min_length=10, max_length=600)
    data_source_label: BenchmarkSourceLabel
    # Strictly offline test-harness simulation fixture (NEVER treated as Live DeepSeek ground truth).
    offline_simulated_semantic: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _check_determinate_consistency(self) -> "BenchmarkCase":
        if self.expected_verdict == "INCONCLUSIVE" and self.ground_truth_determinate:
            raise ValueError("INCONCLUSIVE ground truth cases must set ground_truth_determinate=False.")
        if self.expected_verdict in {"PASS", "FAIL"} and not self.ground_truth_determinate:
            raise ValueError("Determinate PASS/FAIL ground truth cases must set ground_truth_determinate=True.")
        if self.testcase.id != self.case_id:
            raise ValueError(f"testcase.id '{self.testcase.id}' must match case_id '{self.case_id}'.")
        if self.testcase.category != self.category:
            raise ValueError(f"testcase.category '{self.testcase.category}' must match category '{self.category}'.")
        return self


class MismatchAnalysis(BaseModel):
    """Sanitized, secret-free diagnostic record for a benchmark expectation mismatch."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    asi: AsiGroup
    evaluation_scope: str
    expected_verdict: ExpectedVerdictLabel
    actual_verdict: ActualVerdictLabel
    expected_reasoning: str
    actual_reasoning_code: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    judge_invoked_or_bypassed: Literal["invoked", "bypassed"]
    failure_category: FailureCauseCategory
    possible_cause: str = Field(min_length=1, max_length=400)


class CaseEvaluationRecord(BaseModel):
    """Per-case evaluation output emitted by the calibration harness."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    asi: AsiGroup
    split: BenchmarkSplit
    scenario_type: EvidenceScenarioType
    evaluation_scope: str
    scope_family: ScopeFamilyLabel
    data_source_label: BenchmarkSourceLabel
    expected_verdict: ExpectedVerdictLabel
    ground_truth_determinate: bool
    actual_verdict: ActualVerdictLabel
    matched: bool
    decided_by: DecisionAuthorityLabel
    semantic_judge_invoked: bool
    actual_reasoning_code: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    evidence_boundary_violation: bool = False
    boundary_violation_reason: str | None = None
    provider_fault_code: str | None = None
    provider_duration_ms: float | None = None
    token_usage: dict[str, int] | None = None
    mismatch_detail: MismatchAnalysis | None = None


class ConfusionMatrix(BaseModel):
    """3x4 confusion matrix (Expected PASS/FAIL/INCONCLUSIVE vs Actual PASS/FAIL/INCONCLUSIVE/ERROR)."""

    model_config = ConfigDict(extra="forbid")

    matrix: dict[ExpectedVerdictLabel, dict[ActualVerdictLabel, int]]

    @classmethod
    def empty(cls) -> "ConfusionMatrix":
        return cls(
            matrix={
                exp: {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "ERROR": 0}
                for exp in ("PASS", "FAIL", "INCONCLUSIVE")
            }
        )

    def increment(self, expected: ExpectedVerdictLabel, actual: ActualVerdictLabel) -> None:
        self.matrix[expected][actual] += 1


class SliceMetrics(BaseModel):
    """Compact metric slice for per-ASI, per-scope-family, or per-split breakdown."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    determinate_cases: int
    indeterminate_cases: int
    determinate_accuracy: float | None
    exact_match_rate: float
    false_pass_count: int
    false_fail_count: int
    inconclusive_count: int
    justified_inconclusive_count: int
    unnecessary_inconclusive_count: int
    evidence_boundary_violation_count: int
    judge_invocation_count: int


class CalibrationMetrics(BaseModel):
    """Full calibration metrics separating determinate PASS/FAIL accuracy from INCONCLUSIVE handling."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    determinate_cases: int
    indeterminate_cases: int
    overall_determinate_accuracy: float | None
    overall_exact_match_rate: float
    pass_precision: float | None
    pass_recall: float | None
    fail_precision: float | None
    fail_recall: float | None
    false_pass_count: int
    false_pass_rate: float
    false_fail_count: int
    false_fail_rate: float
    inconclusive_count: int
    inconclusive_rate: float
    justified_inconclusive_count: int
    justified_inconclusive_rate: float | None
    unnecessary_inconclusive_count: int
    unnecessary_inconclusive_rate: float | None
    evidence_boundary_violation_count: int
    deterministic_decision_count: int
    llm_judge_decision_count: int
    judge_invocation_count: int
    provider_failure_count: int
    total_provider_duration_ms: float | None = None
    mean_provider_duration_ms: float | None = None
    token_usage: dict[str, int] | None = None
    confusion_matrix: ConfusionMatrix
    by_asi: dict[AsiGroup, SliceMetrics]
    by_scope_family: dict[ScopeFamilyLabel, SliceMetrics]
    by_split: dict[BenchmarkSplit, SliceMetrics]


class CalibrationRunReport(BaseModel):
    """Reproducible output of evaluating one pipeline configuration on the benchmark."""

    model_config = ConfigDict(extra="forbid")

    pipeline_mode: EvaluationPipelineMode
    execution_origin: ExecutionOriginLabel
    is_live_experiment: bool
    provider_label: str
    benchmark_version: str
    benchmark_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    data_source_counts: dict[str, int]
    disclaimer: str
    metrics: CalibrationMetrics
    records: list[CaseEvaluationRecord]
    mismatches: list[MismatchAnalysis]


class PipelineComparisonReport(BaseModel):
    """Side-by-side comparison of Deterministic Baseline (A), Phase 4 Evidence-Aware (B), and LLM Judge + Skills + v2 (C)."""

    model_config = ConfigDict(extra="forbid")

    benchmark_version: str
    benchmark_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_baseline: CalibrationRunReport
    phase4_evidence_aware: CalibrationRunReport
    llm_judge_skills_v2: CalibrationRunReport
    comparison_summary: dict[str, Any]
    disclaimer: str
