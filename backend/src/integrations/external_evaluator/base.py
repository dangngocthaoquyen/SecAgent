"""External semantic evaluator interface, separate from security tools."""

from abc import ABC, abstractmethod

from integrations.external_evaluator.models import EvaluationRequest, ExternalEvaluationOutcome


class ExternalEvaluatorProvider(ABC):
    @abstractmethod
    def evaluate(self, request: EvaluationRequest) -> ExternalEvaluationOutcome:
        """Return a validated recommendation or a provider fault, never a final verdict."""
