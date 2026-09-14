"""Smoke tests for native testcase and payload repositories."""

from pathlib import Path

from payloads import PayloadLoader
from testing import TestCaseLoader


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_pi_001_testcase_loads() -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT / "testcases" / "prompt_injection" / "PI-001.yaml"
    )

    assert testcase.id == "PI-001"
    assert testcase.payload_refs == ["PI-P001"]


def test_prompt_injection_payload_repository_loads() -> None:
    repository = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "prompt_injection.yaml"
    )

    assert repository["PI-P001"].category == "prompt_injection"
    assert "{{instruction}}" in repository["PI-P001"].template
