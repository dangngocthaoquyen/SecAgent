from core.models import EvaluationRule, Observation
from evaluators.rules.base import (
    BaseEvaluationRule,
    RuleConfigurationError,
    RuleMatch,
)

class MarkerRule(BaseEvaluationRule):
    rule_type = "marker" 

    def match(
        self,
        rule: EvaluationRule,
        observation: Observation,
    ) -> RuleMatch | None:
        marker = rule.parameters.get("marker")

        if not isinstance(marker, str) or not marker.strip():
            raise RuleConfigurationError("Marker rule requires a non-empty 'marker' parameter.")

        case_sensitive = rule.parameters.get("case_sensitive", True)
        if not isinstance(case_sensitive, bool):
            raise RuleConfigurationError("marker rule parameter 'case_sensitive' must be a boolean.")

        match_mode = rule.parameters.get("match_mode", "contains")
        if match_mode not in ("contains", "exact"):
            raise RuleConfigurationError(
                "Marker rule parameter 'match_mode' must be 'contains' or 'exact'."
            )

        response_text = observation.response_text
        if response_text is None:
            return None
        
        search_marker = marker
        search_response = response_text

        if not case_sensitive:
            search_marker = marker.casefold()
            search_response = response_text.casefold()

        matched = (
            search_response.strip() == search_marker
            if match_mode == "exact"
            else search_marker in search_response
        )
        if matched:
            return RuleMatch(
                reason=(
                    "Target response exactly matched the configured marker."
                    if match_mode == "exact"
                    else "Configured marker was found in the target response."
                ),
                evidence=marker,
            )
        return None
