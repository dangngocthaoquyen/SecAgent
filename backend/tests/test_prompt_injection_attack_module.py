"""Unit tests for prompt-injection attack metadata preparation."""

import pytest

from attack_modules import PromptInjectionAttackModule
from core.models import EvaluationConfig, TestCase as CoreTestCase
from core.models import TestInput as CoreTestInput


def make_testcase(*, category: str = "prompt_injection") -> CoreTestCase:
    return CoreTestCase(
        id="PI-001",
        name="Direct instruction override",
        category=category,
        attack_type="direct",
        objective="Test instruction override behavior.",
        attack_module="prompt_injection",
        evaluation=EvaluationConfig(
            type="marker_absence",
            marker="PI_TEST_SUCCESS_7F3A",
        ),
    )


def test_prepare_accepts_prompt_injection_category() -> None:
    prepared = PromptInjectionAttackModule().prepare(
        make_testcase(),
        CoreTestInput(id="input-001", prompt="rendered payload"),
    )

    assert prepared.metadata["category"] == "prompt_injection"


def test_prepare_rejects_wrong_category() -> None:
    with pytest.raises(ValueError, match="non-prompt-injection testcase"):
        PromptInjectionAttackModule().prepare(
            make_testcase(category="tool_misuse"),
            CoreTestInput(id="input-001", prompt="rendered payload"),
        )


def test_prepare_adds_attack_metadata() -> None:
    prepared = PromptInjectionAttackModule().prepare(
        make_testcase(),
        CoreTestInput(id="input-001", prompt="rendered payload"),
    )

    assert prepared.metadata == {
        "testcase_id": "PI-001",
        "category": "prompt_injection",
        "attack_type": "direct",
        "attack_module": "prompt_injection",
    }


def test_prepare_does_not_mutate_original_test_input() -> None:
    original = CoreTestInput(
        id="input-001",
        prompt="rendered payload",
        metadata={"source": "native"},
    )
    original_state = original.model_dump()

    prepared = PromptInjectionAttackModule().prepare(make_testcase(), original)

    assert original.model_dump() == original_state
    assert prepared is not original
    assert prepared.metadata["source"] == "native"
