"""Bind testcase rule parameters to a lab fixture before execution.

The YAML schema stays unchanged. Payload templates are rendered separately with
the same effective variables; the evaluator receives an ordinary TestCase.
"""

from collections.abc import Mapping
from typing import Any

from core.models import PayloadTemplate, TestCase
from payloads import PayloadRenderer


def bind_testcase_variables(
    testcase: TestCase,
    overrides: Mapping[str, Any] | None = None,
) -> TestCase:
    """Return a copy with variables merged and rule parameters rendered."""

    data = testcase.model_dump()
    variables = {**testcase.variables, **(overrides or {})}
    data["variables"] = variables
    renderer = PayloadRenderer()

    def bind(value: Any) -> Any:
        if isinstance(value, str):
            template = PayloadTemplate(
                id="testcase-rule-parameter",
                name="Testcase rule parameter",
                category=testcase.category,
                template=value,
            )
            return renderer.render(template, variables)
        if isinstance(value, dict):
            return {key: bind(item) for key, item in value.items()}
        if isinstance(value, list):
            return [bind(item) for item in value]
        return value

    for rule in data["evaluation"]["rules"]:
        rule["parameters"] = bind(rule["parameters"])

    return TestCase.model_validate(data)
