"""Contract and evidence regressions for N2; these do not simulate an AI judge."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from core.models import EvaluationConfig, EvaluationRule, Observation, SemanticEvaluationConfig
from evaluators.rules.marker import MarkerRule
from evaluators.rules.base import RuleConfigurationError
from payloads import PayloadLoader, PayloadRenderer
from testing.testcase_loader import TestCaseLoader

ROOT = Path(__file__).resolve().parents[2]


def test_old_schema_still_loads_without_semantic_configuration():
    config = EvaluationConfig(rules=[EvaluationRule(
        id="legacy", type="marker", verdict="FAIL", parameters={"marker": "test"},
    )])
    assert config.semantic is None
    assert config.strategy is None


@pytest.mark.parametrize("change", [
    {"enabled": "true"}, {"skill": "../../untrusted"},
    {"expected_labels": []}, {"expected_labels": ["UNCLEAR", "UNCLEAR"]},
    {"expected_labels": [" "]}, {"trusted_context": {}}, {"unexpected": "policy"},
])
def test_invalid_semantic_configuration_is_rejected(change):
    config = {
        "enabled": True, "skill": "goal_hijacking",
        "trusted_context": {"original_goal": "Summarize"}, "expected_labels": ["UNCLEAR"],
    }
    with pytest.raises(ValidationError):
        SemanticEvaluationConfig.model_validate(config | change)


@pytest.mark.parametrize(("parameters", "response", "matches"), [
    ({}, 'I refuse to emit "MARKER".', True),  # legacy substring preserved
    ({"match_mode": "exact"}, 'I refuse to emit "MARKER".', False),
    ({"match_mode": "exact"}, "Summary MARKER", False),
    ({"match_mode": "exact"}, "\n MARKER \t", True),
    ({"match_mode": "exact", "case_sensitive": False}, "marker", True),
    ({"match_mode": "exact"}, None, False),
])
def test_marker_mode_is_generic_and_opt_in(parameters, response, matches):
    rule = EvaluationRule(id="marker", type="marker", verdict="FAIL", parameters={"marker": "MARKER"} | parameters)
    assert (MarkerRule().match(rule, Observation(response_text=response)) is not None) == matches


@pytest.mark.parametrize("mode", ["prefix", False, None, [], {}])
def test_bad_marker_mode_rejected_even_without_response(mode):
    rule = EvaluationRule(id="marker", type="marker", verdict="FAIL", parameters={"marker": "X", "match_mode": mode})
    with pytest.raises(RuleConfigurationError):
        MarkerRule().match(rule, Observation())
