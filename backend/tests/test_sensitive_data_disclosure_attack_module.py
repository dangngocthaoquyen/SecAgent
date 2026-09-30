"""Tests for SD input preparation and registry integration."""

from pathlib import Path

import pytest

from attack_modules import (
    BaseAttackModule,
    PromptInjectionAttackModule,
    SensitiveDataDisclosureAttackModule,
    ToolMisuseAttackModule,
    build_default_attack_module_registry,
)
from core.models import TestCase as CoreTestCase
from core.models import TestInput as CoreTestInput
from payloads import PayloadLoader, PayloadRenderer
from testing.testcase_loader import TestCaseLoader


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CANARY = "SECAGENT_CANARY_SD_9F2A"


def load_sd_testcase(case_id: str = "SD-001") -> CoreTestCase:
    return TestCaseLoader().load(
        REPOSITORY_ROOT
        / "testcases"
        / "sensitive_data_disclosure"
        / f"{case_id}.yaml"
    )


@pytest.mark.parametrize("case_id", ["SD-001", "SD-002", "SD-C01"])
def test_prepare_real_sd_payload(case_id: str) -> None:
    testcase = load_sd_testcase(case_id)

    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "sensitive_data_disclosure.yaml"
    )
    payload = payloads[testcase.payload_refs[0]]

    assert payload.category == testcase.category

    rendered_prompt = PayloadRenderer().render(
        payload,
        testcase.variables,
    )

    original = CoreTestInput(
        id=f"{case_id}-input",
        prompt=rendered_prompt,
        payload_ref=payload.id,
        metadata={
            "source": "native",
            "testcase_id": "stale-id",
        },
    )

    original_state = original.model_dump()
    testcase_state = testcase.model_dump()

    prepared = SensitiveDataDisclosureAttackModule().prepare(
        testcase,
        original,
    )

    assert prepared is not original
    assert original.model_dump() == original_state
    assert testcase.model_dump() == testcase_state

    assert prepared.prompt == rendered_prompt
    assert CANARY not in rendered_prompt
    assert "{{" not in rendered_prompt

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


@pytest.mark.parametrize("category", ["prompt_injection", "tool_misuse"])
def test_prepare_rejects_wrong_category(category: str) -> None:
    testcase = load_sd_testcase().model_copy(
        deep=True,
        update={"category": category},
    )

    with pytest.raises(
        ValueError,
        match="non-sensitive-data-disclosure testcase",
    ):
        SensitiveDataDisclosureAttackModule().prepare(
            testcase,
            CoreTestInput(id="wrong-category", prompt="Any prompt"),
        )


def test_prepared_input_has_independent_nested_data() -> None:
    original = CoreTestInput(
        id="nested-input",
        prompt="Request a private value.",
        metadata={
            "context": {
                "labels": ["original"],
            }
        },
        parameters={
            "options": {
                "labels": ["original"],
            }
        },
    )
    original_state = original.model_dump()

    prepared = SensitiveDataDisclosureAttackModule().prepare(
        load_sd_testcase(),
        original,
    )

    prepared.metadata["context"]["labels"].append("prepared")
    prepared.parameters["options"]["labels"].append("prepared")

    assert original.model_dump() == original_state


@pytest.mark.parametrize(
    ("module_name", "expected_type"),
    [
        ("prompt_injection", PromptInjectionAttackModule),
        ("tool_misuse", ToolMisuseAttackModule),
        (
            "sensitive_data_disclosure",
            SensitiveDataDisclosureAttackModule,
        ),
    ],
)
def test_default_registry_resolves_supported_modules(
    module_name: str,
    expected_type: type[BaseAttackModule],
) -> None:
    registry = build_default_attack_module_registry()

    module = registry.resolve(module_name)

    assert isinstance(module, expected_type)