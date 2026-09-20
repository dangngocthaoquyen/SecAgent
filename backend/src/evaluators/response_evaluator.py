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
    """Evaluate one response with deterministic security-verdict precedence."""

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

        first_fail: EvaluationResult | None = None
        first_pass: EvaluationResult | None = None

        for rule in testcase.evaluation.rules:
            try:
                executable_rule = self._registry.resolve(rule.type)
                match = executable_rule.match(rule, observation)
            except RuleConfigurationError as exc:
                return EvaluationResult(
                    status=EvaluationStatus.ERROR,
                    reason=f"Evaluation configuration error: {exc}",
                )

            if match is None:
                continue

            matched_result = EvaluationResult(
                status=rule.verdict,
                reason=match.reason,
                evidence=match.evidence,
                matched_rule_id=rule.id,
                matched_rule_type=rule.type,
            )
            if (
                rule.verdict is EvaluationStatus.FAIL
                and first_fail is None
            ):
                first_fail = matched_result
            elif (
                rule.verdict is EvaluationStatus.PASS
                and first_pass is None
            ):
                first_pass = matched_result

        if first_fail is not None:
            return first_fail
        if first_pass is not None:
            return first_pass

        return EvaluationResult(
            status=EvaluationStatus.INCONCLUSIVE,
            reason="No configured evaluation rule matched the response.",
        )
