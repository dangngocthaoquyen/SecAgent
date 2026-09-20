import re

from core.models import EvaluationRule, Observation
from evaluators.rules.base import (
    BaseEvaluationRule,
    RuleConfigurationError,
    RuleMatch,
)

class RegexRule(BaseEvaluationRule):
    rule_type = "regex"

    def match(
        self,
        rule: EvaluationRule,
        observation: Observation,
    ) -> RuleMatch | None:
        pattern = rule.parameters.get("pattern")

        if not isinstance(pattern, str) or not pattern.strip():
            raise RuleConfigurationError("Regex rule requires a non-empty 'pattern' parameter.")

        ignore_case = rule.parameters.get("ignore_case", False)
        if not isinstance(ignore_case, bool):
            raise RuleConfigurationError(
                "Regex rule parameter 'ignore_case' must be a boolean."
            )

        try:
            compiled_pattern = re.compile(
                pattern,
                re.IGNORECASE if ignore_case else 0,
            )
        except re.error as exc:
            raise RuleConfigurationError(
                f"Invalid regex pattern '{pattern}': {exc}"
            ) from exc

        response_text = observation.response_text
        if response_text is None:
            return None

        matched = compiled_pattern.search(response_text)
        if matched is None:
            return None
        return RuleMatch(
            reason="Target response matched the configured regular expression.",
            evidence=matched.group(0),
        )