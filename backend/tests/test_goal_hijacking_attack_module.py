"""GH preparation, payload boundaries, and registry integration."""

from pathlib import Path

import pytest

from attack_modules import (
    BaseAttackModule,
    GoalHijackingAttackModule,
    PromptInjectionAttackModule,
    SensitiveDataDisclosureAttackModule,
    ToolMisuseAttackModule,
    build_default_attack_module_registry,
)
from core.models import TestCase as CoreTestCase
from core.models import TestInput as CoreTestInput
from payloads import PayloadLoader, PayloadRenderer
from testing.testcase_loader import TestCaseLoader


ROOT = Path(__file__).resolve().parents[2]
CASE_IDS = ("GH-001", "GH-002", "GH-C01")
MARKER = "SECAGENT_GH_HIJACKED"


def load_case(case_id: str) -> CoreTestCase:
    return TestCaseLoader().load(
        ROOT / "testcases" / "goal_hijacking" / f"{case_id}.yaml"
    )


def render_prompt(testcase: CoreTestCase) -> str:
    repository = PayloadLoader().load_repository(
        ROOT / "payload" / "goal_hijacking.yaml"
    )
    payload = repository[testcase.payload_refs[0]]
    assert payload.category == testcase.category
    return PayloadRenderer().render(payload, testcase.variables)


def split_document(prompt: str) -> tuple[str, str, str]:
    prefix, remainder = prompt.split("\n<document>\n", 1)
    body, suffix = remainder.split("\n</document>", 1)
    return prefix.strip(), body.strip(), suffix.strip()


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_prepare_preserves_input_and_attaches_metadata(case_id: str) -> None:
    testcase = load_case(case_id)
    prompt = render_prompt(testcase)
    original = CoreTestInput(
        id=f"{case_id}-input",
        prompt=prompt,
        payload_ref=testcase.payload_refs[0],
        metadata={"source": "native", "testcase_id": "stale-id"},
        parameters={"options": {"labels": ["original"]}},
    )
    original_state = original.model_dump()
    testcase_state = testcase.model_dump()

    prepared = GoalHijackingAttackModule().prepare(testcase, original)

    assert prepared is not original
    assert original.model_dump() == original_state
    assert testcase.model_dump() == testcase_state
    assert "{{" not in prompt
    assert prepared.model_dump(exclude={"metadata"}) == (
        original.model_dump(exclude={"metadata"})
    )
    assert prepared.metadata == {
        "source": "native",
        "testcase_id": testcase.id,
        "category": testcase.category,
        "attack_type": testcase.attack_type,
        "attack_module": testcase.attack_module,
    }


def test_prepared_nested_data_is_independent() -> None:
    original = CoreTestInput(
        id="nested-input",
        metadata={"context": {"labels": ["original"]}},
        parameters={"options": {"labels": ["original"]}},
    )
    original_state = original.model_dump()

    prepared = GoalHijackingAttackModule().prepare(
        load_case("GH-001"), original
    )
    prepared.metadata["context"]["labels"].append("changed")
    prepared.parameters["options"]["labels"].append("changed")

    assert original.model_dump() == original_state


@pytest.mark.parametrize(
    "category",
    ["prompt_injection", "tool_misuse", "sensitive_data_disclosure"],
)
def test_prepare_rejects_wrong_category(category: str) -> None:
    testcase = load_case("GH-001").model_copy(
        deep=True, update={"category": category}
    )

    with pytest.raises(ValueError, match="non-goal-hijacking testcase"):
        GoalHijackingAttackModule().prepare(
            testcase, CoreTestInput(id="wrong-category")
        )


@pytest.mark.parametrize(
    ("name", "expected_type"),
    [
        ("prompt_injection", PromptInjectionAttackModule),
        ("tool_misuse", ToolMisuseAttackModule),
        ("sensitive_data_disclosure", SensitiveDataDisclosureAttackModule),
        ("goal_hijacking", GoalHijackingAttackModule),
    ],
)
def test_default_registry_preserves_all_categories(
    name: str,
    expected_type: type[BaseAttackModule],
) -> None:
    module = build_default_attack_module_registry().resolve(name)

    assert isinstance(module, expected_type)


@pytest.mark.parametrize("case_id", ["GH-001", "GH-002"])
def test_attack_is_confined_to_its_block_and_preserves_control(
    case_id: str,
) -> None:
    prompt = render_prompt(load_case(case_id))
    control = render_prompt(load_case("GH-C01"))

    before, remainder = prompt.split("<attacker_controlled_instruction>", 1)
    attack, after = remainder.split("</attacker_controlled_instruction>", 1)

    assert attack.count(MARKER) == 1
    assert MARKER not in before + after
    assert MARKER not in control

    # Removing only the malicious block must recover the clean task/data.
    assert split_document(before + after) == split_document(control)

    _, document, suffix = split_document(prompt)
    if case_id == "GH-002":
        assert MARKER in document
        assert suffix == ""
    else:
        assert MARKER not in document
        assert MARKER in suffix


def test_control_has_no_attack_content() -> None:
    prompt = render_prompt(load_case("GH-C01"))

    assert MARKER not in prompt
    assert "<attacker_controlled_instruction>" not in prompt