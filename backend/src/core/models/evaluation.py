from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


class EvaluationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvaluationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    verdict: EvaluationStatus
    parameters: dict[str, Any] = Field(default_factory=dict)

#Đoạn này đảm bảo ID không thể chỉ toàn khoảng trắng.
    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("Evaluation rule id must not be blank")
        return normalized_value

#Bo khoang trang & chuyen lowercase
    @field_validator("type")
    @classmethod
    def validate_type(cls, value: str) -> str:
        normalized_value = value.strip().lower()
        if not normalized_value:
            raise ValueError("Evaluation rule type must not be blank")
        return normalized_value

    @field_validator("verdict")
    @classmethod
    def validate_security_verdict(
        cls,
        value: EvaluationStatus,
    ) -> EvaluationStatus:
        if value not in {EvaluationStatus.PASS, EvaluationStatus.FAIL}:
            raise ValueError(
                "Evaluation rule verdict must be PASS or FAIL."
            )
        return value


class SemanticEvaluationConfig(BaseModel):
    """Opt-in data for an external evaluator; does not invoke a provider."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(default=False, strict=True)
    skill: Literal[
        "goal_hijacking", "prompt_injection", "tool_misuse",
        "sensitive_data_disclosure",
    ]
    trusted_context: dict[str, Any] = Field(min_length=1)
    expected_labels: list[str] = Field(min_length=1)

    @field_validator("expected_labels")
    @classmethod
    def labels_must_be_unique_and_nonblank(cls, labels: list[str]) -> list[str]:
        if any(not label.strip() or label != label.strip() for label in labels):
            raise ValueError("Semantic labels must be nonblank and trimmed.")
        if len(set(labels)) != len(labels):
            raise ValueError("Semantic labels must be unique.")
        return labels


class EvaluationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[EvaluationRule] = Field(min_length=1)
    strategy: Literal["deterministic", "action", "semantic", "hybrid"] | None = None
    semantic: SemanticEvaluationConfig | None = None

    @field_validator("rules")
    @classmethod
    def rule_ids_must_be_unique(
        cls,
        rules: list[EvaluationRule],
    ) -> list[EvaluationRule]:
        seen_ids: set[str] = set()
        for rule in rules:
            if rule.id in seen_ids:
                raise ValueError(f"Duplicate evaluation rule id: {rule.id!r}.")
            seen_ids.add(rule.id)
        return rules


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: EvaluationStatus
    reason: str = Field(min_length=1)
    evidence: str | None = None
    matched_rule_id: str | None = None
    matched_rule_type: str | None = None

    @computed_field
    @property
    def passed(self) -> bool:
        return self.status == EvaluationStatus.PASS
