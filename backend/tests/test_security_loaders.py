"""Smoke tests for native testcase and payload repositories."""

from pathlib import Path

import pytest

from payloads import PayloadLoader
from payloads import PayloadRenderer
from attack_modules import ToolMisuseAttackModule
from core.models import TestInput as CoreTestInput
from testing import TestCaseLoader


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("testcase_id", "payload_ref"),
    [
        ("PI-001", "PI-P001"),
        ("PI-002", "PI-P002"),
        ("PI-003", "PI-P003"),
    ],
)
def test_prompt_injection_testcase_loads(
    testcase_id: str,
    payload_ref: str,
) -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT
        / "testcases"
        / "prompt_injection"
        / f"{testcase_id}.yaml"
    )

    assert testcase.id == testcase_id
    assert testcase.payload_refs == [payload_ref]


def test_prompt_injection_payload_repository_loads() -> None:
    repository = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "prompt_injection.yaml"
    )

    assert repository["PI-P001"].category == "prompt_injection"
    assert "{{instruction}}" in repository["PI-P001"].template


def test_tm002_loads_renders_and_prepares_structured_tool_input() -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT / "testcases" / "tool_misuse" / "TM-002.yaml"
    )
    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "tool_misuse.yaml"
    )
    command = PayloadRenderer().render(
        payloads[testcase.payload_refs[0]], testcase.variables
    )
    original = CoreTestInput(
        id="tm002-input",
        parameters={
            "tool_call": {
                "name": testcase.variables["tool_name"],
                "arguments": {"command": command},
            }
        },
    )

    prepared = ToolMisuseAttackModule().prepare(testcase, original)

    assert testcase.id == "TM-002"
    assert command == "echo SECAGENT_TOOLBOT_TM002"
    assert prepared.parameters == original.parameters
    assert prepared.metadata["testcase_id"] == "TM-002"
    assert len(testcase.evaluation.rules) == 1
    assert testcase.evaluation.rules[0].verdict.value == "FAIL"


def test_tm001_agent_driven_scenario_remains_unchanged() -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT / "testcases" / "tool_misuse" / "TM-001.yaml"
    )
    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "tool_misuse.yaml"
    )
    prompt = PayloadRenderer().render(
        payloads[testcase.payload_refs[0]], testcase.variables
    )
    prepared = ToolMisuseAttackModule().prepare(
        testcase,
        CoreTestInput(id="tm001-input", prompt=prompt),
    )

    assert testcase.attack_type == (
        "sensitive_tool_invocation_without_confirmation"
    )
    assert testcase.variables["sensitive_tool"] == "PerformSensitiveAction"
    assert prepared.prompt == prompt
    assert "PerformSensitiveAction" in (prepared.prompt or "")
    assert [rule.parameters["mode"] for rule in testcase.evaluation.rules] == [
        "present",
        "absent",
    ]
