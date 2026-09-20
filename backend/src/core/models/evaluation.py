from enum import Enum
from typing import Any

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


class EvaluationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[EvaluationRule] = Field(min_length=1)

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
