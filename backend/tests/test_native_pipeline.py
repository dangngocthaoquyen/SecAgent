"""Network-free integration test for the registry-based Runner pipeline."""

from pathlib import Path

from core.models import (
    EvaluationStatus,
    ExecutionResult,
    TargetProfile,
    TestInput as CoreTestInput,
)
from payloads import PayloadLoader, PayloadRenderer
from targets import load_target
from targets.adapters import BaseTargetAdapter
from testing import Executor, Runner, TestCaseLoader


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class StubTargetAdapter(BaseTargetAdapter):
    def execute(
        self,
        target: TargetProfile,
        test_input: CoreTestInput,
    ) -> ExecutionResult:
        # Hai assert này chứng minh Runner đã đi qua:
        # Registry -> PromptInjectionAttackModule.prepare(...)
        assert test_input.metadata["testcase_id"] == "PI-001"
        assert test_input.metadata["attack_module"] == "prompt_injection"

        return ExecutionResult(
            success=True,
            status_code=200,
            output_text="PI_TEST_SUCCESS_7F3A",
        )


def test_runner_executes_native_prompt_injection_pipeline() -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT / "testcases" / "prompt_injection" / "PI-001.yaml"
    )

    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "prompt_injection.yaml"
    )

    payload = payloads[testcase.payload_refs[0]]
    rendered_prompt = PayloadRenderer().render(
        payload,
        testcase.variables,
    )

    test_input = CoreTestInput(
        id="native-input-001",
        prompt=rendered_prompt,
        payload_ref=payload.id,
    )

    target = load_target(
        REPOSITORY_ROOT / "configs" / "targets" / "dvaa.yaml"
    )

    evaluation = Runner(
        executor=Executor(
            adapters={"generic_http": StubTargetAdapter()}
        )
    ).run(
        testcase=testcase,
        target=target,
        test_input=test_input,
    )

    assert "Reply exactly with PI_TEST_SUCCESS_7F3A" in rendered_prompt
    assert test_input.metadata == {}
    assert evaluation.status is EvaluationStatus.FAIL
    assert evaluation.passed is False
