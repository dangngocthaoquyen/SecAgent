"""Week 5 v1.0 request, Judge response, and provider-fault contracts."""

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.models import EvaluationStatus, Evidence
from integrations.external_evaluator.identity import canonical_hash


EvaluationType = Literal[
    "goal_hijacking", "prompt_injection", "tool_misuse", "sensitive_data_disclosure",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequestTestcase(StrictModel):
    id: str = Field(min_length=1)
    security_objective: str = Field(min_length=1)


class RequestObservation(StrictModel):
    response_text: str | None
    evidence: list[dict[str, Any]]
    metadata: dict[str, Any]

    @field_validator("evidence")
    @classmethod
    def normalized_evidence(cls, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in items:
            Evidence.model_validate(item)
        return items

    @field_validator("metadata")
    @classmethod
    def no_raw_transport(cls, metadata: dict[str, Any]) -> dict[str, Any]:
        if {"response_headers", "raw_output", "credentials"} & metadata.keys():
            raise ValueError("Raw transport or credential metadata is not Judge input.")
        return metadata


class SkillIdentity(StrictModel):
    id: Literal["security"]
    version: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class EvaluationRequest(StrictModel):
    schema_version: Literal["1.0"]
    request_id: str = Field(min_length=1)
    evaluation_type: EvaluationType
    testcase: RequestTestcase
    trusted_context: dict[str, Any] = Field(min_length=1)
    observation: RequestObservation
    expected_labels: list[str] = Field(min_length=1)
    skill: SkillIdentity

    @field_validator("expected_labels")
    @classmethod
    def labels_are_unique(cls, labels: list[str]) -> list[str]:
        if any(not item.strip() or item != item.strip() for item in labels):
            raise ValueError("Expected labels must be nonblank and trimmed.")
        if len(labels) != len(set(labels)):
            raise ValueError("Expected labels must be unique.")
        return labels

    @property
    def sha256(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class JudgeEvidence(StrictModel):
    type: Literal["response_span", "runtime_reference"]
    value: str = Field(min_length=1)

    @field_validator("value")
    @classmethod
    def nonblank_value(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Evidence citation must not be blank.")
        return value


class ExternalEvaluationResult(StrictModel):
    verdict: EvaluationStatus
    classification: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)
    reason: str = Field(min_length=1)
    evidence: list[JudgeEvidence]

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Reason must not be blank.")
        return value


class ProviderFaultCode(str, Enum):
    JUDGE_DISABLED = "judge_disabled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SKILL_UNAVAILABLE = "skill_unavailable"
    SKILL_MISMATCH = "skill_mismatch"
    EXECUTABLE_MISSING = "executable_missing"
    TIMEOUT = "timeout"
    NONZERO_EXIT = "nonzero_exit"
    OUTPUT_LIMIT = "output_limit"
    INVALID_OUTPUT = "invalid_output"
    PROCESS_ERROR = "process_error"


class ProviderFault(StrictModel):
    code: ProviderFaultCode
    message: str = Field(min_length=1)


class ExternalEvaluationOutcome(StrictModel):
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    skill: SkillIdentity | None
    result: ExternalEvaluationResult | None = None
    fault: ProviderFault | None = None
    duration_ms: float = Field(ge=0, allow_inf_nan=False)
    exit_code: int | None = None

    @model_validator(mode="after")
    def exactly_one_result_or_fault(self) -> "ExternalEvaluationOutcome":
        if (self.result is None) == (self.fault is None):
            raise ValueError("Provider outcome requires exactly one result or fault.")
        return self
