"""Public exports for the core Pydantic models."""

from core.models.evaluation import (
    EvaluationConfig,
    EvaluationResult,
    EvaluationRule,
    EvaluationStatus,
    SemanticEvaluationConfig,
)
from core.models.execution import ExecutionResult
from core.models.observation import Observation
from core.models.payload import PayloadTemplate
from core.models.target import TargetInterface, TargetProfile
from core.models.test_input import TestInput
from core.models.testcase import (
    ExternalReference,
    TaxonomyReference,
    TestCase,
    TestCaseTaxonomy,
)
from core.models.evidence import Evidence
from core.models.evidence_v2 import (
    EVIDENCE_CONTRACT_V2_VERSION,
    CorrelationContextV2,
    EvidenceContractV2,
    EvidenceFindingV2,
    ExecutionObservationRecordV2,
    ObservationCoverageV2,
    ResponseObservationV2,
    ScopeAlignmentV2,
    ToolIntentRecordV2,
)

__all__ = [
    "EvaluationConfig",
    "EvaluationResult",
    "EvaluationStatus",
    "SemanticEvaluationConfig",
    "ExecutionResult",
    "ExternalReference",
    "Observation",
    "PayloadTemplate",
    "TargetInterface",
    "TargetProfile",
    "TaxonomyReference",
    "TestInput",
    "TestCase",
    "TestCaseTaxonomy",
    "EvaluationRule",
    "Evidence",
    "EVIDENCE_CONTRACT_V2_VERSION",
    "CorrelationContextV2",
    "EvidenceContractV2",
    "EvidenceFindingV2",
    "ExecutionObservationRecordV2",
    "ObservationCoverageV2",
    "ResponseObservationV2",
    "ScopeAlignmentV2",
    "ToolIntentRecordV2",
]
