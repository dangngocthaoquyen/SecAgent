from core.models import EvaluationRule, Observation
from evaluators.rules.base import (
    BaseEvaluationRule,
    RuleConfigurationError,
    RuleMatch,
)


class KeywordRule(BaseEvaluationRule):
    rule_type = "keyword"

    def match(
        self,
        rule: EvaluationRule,
        observation: Observation,
    ) -> RuleMatch | None:
        keywords = rule.parameters.get("keywords")

        if (
            not isinstance(keywords, list)
            or not keywords
            or not all(
                isinstance(keyword, str) and keyword.strip()
                for keyword in keywords
            )
        ):
            raise RuleConfigurationError(
                "keyword rule requires a non-empty 'keywords' list "
                "containing non-empty strings."
            )

        case_sensitive = rule.parameters.get("case_sensitive", False)

        if not isinstance(case_sensitive, bool):
            raise RuleConfigurationError(
                "keyword rule parameter 'case_sensitive' must be a boolean."
            )

        response_text = observation.response_text

        if response_text is None:
            return None

        searchable_response = (
            response_text
            if case_sensitive
            else response_text.casefold()
        )

        for keyword in keywords:
            searchable_keyword = (
                keyword
                if case_sensitive
                else keyword.casefold()
            )

            if searchable_keyword in searchable_response:
                return RuleMatch(
                    reason=(
                        "Configured keyword was found "
                        "in the target response."
                    ),
                    evidence=keyword,
                )

        return None