from collections.abc import Iterable

from evaluators.rules import (
    BaseEvaluationRule,
    KeywordRule,
    MarkerRule,
    RegexRule,
    RuleConfigurationError,
    StatusCodeRule,
    ToolCallRule,
)

class EvaluationRuleRegistry:
    """Map YAML rule type strings to executable rule implementations."""

    def __init__(
        self,
        rules: Iterable[BaseEvaluationRule] = (),
    ) -> None:
        self._rules: dict[str, BaseEvaluationRule] = {}

        for rule in rules:
            self.register(rule)

    def register(self, rule: BaseEvaluationRule) -> None:
        rule_type = rule.rule_type.strip().lower()

        if not rule_type:
            raise RuleConfigurationError(
                "Registered rule type must not be blank."
            )

        if rule_type in self._rules:
            raise RuleConfigurationError(
                f"Rule type is already registered: {rule_type!r}."
            )
        self._rules[rule_type] = rule

    def resolve(self, rule_type: str) -> BaseEvaluationRule:
        normalized_type = rule_type.strip().lower()

        try:
            return self._rules[normalized_type]
        except KeyError as exc:
            raise RuleConfigurationError(
                f"Unsupported evaluation rule type: {rule_type!r}."
            ) from exc

def build_default_registry() -> EvaluationRuleRegistry:
    return EvaluationRuleRegistry(
        rules=[
            MarkerRule(),
            KeywordRule(),
            RegexRule(),
            StatusCodeRule(),
            ToolCallRule(),
        ]
    )