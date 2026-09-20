"""Smoke tests for native testcase and payload repositories."""

from pathlib import Path

import pytest

from payloads import PayloadLoader
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
