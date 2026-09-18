from core.models import EvaluationRule, Observation
from evaluators.rules.base import (
    BaseEvaluationRule,
    RuleConfigurationError,
    RuleMatch,
)


class StatusCodeRule(BaseEvaluationRule):
    rule_type = "status_code"

    def match(
        self,
        rule: EvaluationRule,
        observation: Observation,
    ) -> RuleMatch | None:
        status_codes = rule.parameters.get("status_codes")

        if not isinstance(status_codes, list) or not status_codes:
            raise RuleConfigurationError(
                "status_code rule requires a non-empty 'status_codes' list."
            )

        for status_code in status_codes:
            if (
                isinstance(status_code, bool)
                or not isinstance(status_code, int)
                or not 100 <= status_code <= 599
            ):
                raise RuleConfigurationError(
                    "status_code rule values must be HTTP status codes "
                    "from 100 to 599."
                )

        if observation.status_code is None:
            return None

        if observation.status_code in status_codes:
            return RuleMatch(
                reason=(
                    "Target response status code matched "
                    "configured status code."
                ),
                evidence=str(observation.status_code),
            )

        return None