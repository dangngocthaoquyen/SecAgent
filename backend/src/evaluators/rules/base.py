"""Shared contracts for deterministic evaluation rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from core.models import EvaluationRule, Observation


class RuleConfigurationError(ValueError):
    """Raised when an evaluation rule has invalid configuration."""


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """Evidence returned when one evaluation rule matches."""

    reason: str
    evidence: str | None = None


class BaseEvaluationRule(ABC):
    """Base interface for executable deterministic rules."""

    rule_type: ClassVar[str]

    @abstractmethod
    def match(
        self,
        rule: EvaluationRule,
        observation: Observation,
    ) -> RuleMatch | None:
        """
        Return RuleMatch when matched.
        Return None when not matched.
        Raise RuleConfigurationError for invalid rule parameters.
        """