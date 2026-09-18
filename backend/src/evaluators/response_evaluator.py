from core.models import (
    EvaluationResult,
    EvaluationStatus,
    Observation,
    TestCase,
)
from evaluators.base import BaseEvaluator
from evaluators.registry import (
    EvaluationRuleRegistry,
    build_default_registry,
)
from evaluators.rules import RuleConfigurationError

class ResponseEvaluator(BaseEvaluator):
    """Evaluate one textual target response using ordered deterministic rules."""

    def __init__(
        self,
        registry: EvaluationRuleRegistry | None = None,
    ) -> None:
        self._registry = (
            registry
            if registry is not None
            else build_default_registry()
        )

    def evaluate(
        self,
        testcase: TestCase,
        observation: Observation,
    ) -> EvaluationResult:
        execution_success = observation.metadata.get("execution_success")
        execution_error = observation.metadata.get("execution_error")

        if execution_success is not True:
            error_text = (
                str(execution_error)
                if execution_error
                else "execution state was unavailable"
            )

            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason=f"Execution failed: {error_text}",
                evidence=str(execution_error) if execution_error else None,
            )

        if observation.response_text is None:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason="No response text was available for evaluation.",
            )

        for rule in testcase.evaluation.rules:
            try:
                executable_rule = self._registry.resolve(rule.type)
                match = executable_rule.match(rule, observation)
            except RuleConfigurationError as exc:
                return EvaluationResult(
                    status=EvaluationStatus.ERROR,
                    reason=f"Evaluation configuration error: {exc}",
                )

            if match is not None:
                return EvaluationResult(
                    status=rule.verdict,
                    reason=match.reason,
                    evidence=match.evidence,
                    matched_rule_id=rule.id,
                    matched_rule_type=rule.type,
                )

        return EvaluationResult(
            status=EvaluationStatus.INCONCLUSIVE,
            reason="No configured evaluation rule matched the response.",
        )
