"""Unit tests for orchestration-only Runner behavior."""

from attack_modules import AttackModuleRegistry, BaseAttackModule
from core.models import (
    EvaluationConfig,
    EvaluationResult,
    EvaluationRule,
    EvaluationStatus,
    ExecutionResult,
    Observation,
    TargetInterface,
    TargetProfile,
    TestCase as CoreTestCase,
    TestInput as CoreTestInput,
)
from evaluators import ResponseEvaluator
from observers import ResponseObserver
from testing import Runner


class StubAttackModule(BaseAttackModule):
    def __init__(
        self,
        *,
        prepared_input: CoreTestInput | None = None,
        error: Exception | None = None,
    ) -> None:
        self.prepared_input = prepared_input
        self.error = error
        self.calls: list[tuple[CoreTestCase, CoreTestInput]] = []

    def prepare(
        self,
        testcase: CoreTestCase,
        test_input: CoreTestInput,
    ) -> CoreTestInput:
        self.calls.append((testcase, test_input))
        if self.error is not None:
            raise self.error
        if self.prepared_input is None:
            raise AssertionError("Prepared input was not configured")
        return self.prepared_input


class RecordingRegistry(AttackModuleRegistry):
    def __init__(self, module: BaseAttackModule) -> None:
        super().__init__({"test_attack": module})
        self.resolve_calls: list[str] = []

    def resolve(self, name: str) -> BaseAttackModule:
        self.resolve_calls.append(name)
        return super().resolve(name)


class StubExecutor:
    def __init__(
        self,
        *,
        result: ExecutionResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[TargetProfile, CoreTestInput]] = []

    def execute(
        self,
        target: TargetProfile,
        test_input: CoreTestInput,
    ) -> ExecutionResult:
        self.calls.append((target, test_input))
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("Execution result was not configured")
        return self.result


class StubObserver:
    def __init__(
        self,
        *,
        observation: Observation | None = None,
        error: Exception | None = None,
    ) -> None:
        self.observation = observation
        self.error = error
        self.calls: list[ExecutionResult] = []

    def observe(self, result: ExecutionResult) -> Observation:
        self.calls.append(result)
        if self.error is not None:
            raise self.error
        if self.observation is None:
            raise AssertionError("Observation was not configured")
        return self.observation


class StubEvaluator:
    def __init__(
        self,
        *,
        result: EvaluationResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[CoreTestCase, Observation]] = []

    def evaluate(
        self,
        testcase: CoreTestCase,
        observation: Observation,
    ) -> EvaluationResult:
        self.calls.append((testcase, observation))
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("Evaluation result was not configured")
        return self.result


class RecordingResponseObserver(ResponseObserver):
    def __init__(self) -> None:
        self.calls: list[ExecutionResult] = []

    def observe(self, result: ExecutionResult) -> Observation:
        self.calls.append(result)
        return super().observe(result)


class RecordingResponseEvaluator(ResponseEvaluator):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[CoreTestCase, Observation]] = []

    def evaluate(
        self,
        testcase: CoreTestCase,
        observation: Observation,
    ) -> EvaluationResult:
        self.calls.append((testcase, observation))
        return super().evaluate(testcase, observation)


def make_testcase(*, attack_module: str = "test_attack") -> CoreTestCase:
    return CoreTestCase(
        id="testcase-001",
        name="Runner testcase",
        category="generic-test",
        objective="Exercise Runner orchestration.",
        attack_module=attack_module,
        evaluation=EvaluationConfig(
            rules=[
                EvaluationRule(
                    id="marker-rule",
                    type="marker",
                    verdict=EvaluationStatus.FAIL,
                    parameters={"marker": "MATCH"},
                )
            ]
        ),
    )


def make_target() -> TargetProfile:
    return TargetProfile(
        id="target-001",
        name="Generic target",
        target_type="service",
        interface=TargetInterface(
            type="http",
            adapter="generic_http",
            config={
                "url": "https://example.invalid/execute",
                "method": "POST",
            },
        ),
    )


def make_registry(module: BaseAttackModule) -> RecordingRegistry:
    return RecordingRegistry(module)


def test_happy_path_uses_registry_and_passes_prepared_input_to_executor() -> None:
    testcase = make_testcase()
    target = make_target()
    original_input = CoreTestInput(id="input-original", prompt="original")
    prepared_input = CoreTestInput(id="input-prepared", prompt="prepared")
    execution = ExecutionResult(
        success=True,
        status_code=200,
        output_text="response",
    )
    observation = Observation(
        response_text="response",
        metadata={"execution_success": True},
    )
    expected = EvaluationResult(
        status=EvaluationStatus.PASS,
        reason="Evaluator result",
    )
    module = StubAttackModule(prepared_input=prepared_input)
    registry = make_registry(module)
    executor = StubExecutor(result=execution)
    observer = StubObserver(observation=observation)
    evaluator = StubEvaluator(result=expected)

    result = Runner(
        executor=executor,
        observer=observer,
        evaluator=evaluator,
        attack_module_registry=registry,
    ).run(testcase, target, original_input)

    assert result is expected
    assert registry.resolve_calls == ["test_attack"]
    assert module.calls == [(testcase, original_input)]
    assert executor.calls == [(target, prepared_input)]
    assert observer.calls == [execution]
    assert evaluator.calls == [(testcase, observation)]


def test_unknown_attack_module_returns_resolution_error() -> None:
    result = Runner(
        attack_module_registry=AttackModuleRegistry(),
    ).run(
        make_testcase(attack_module="unknown"),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Attack module resolution failed."


def test_attack_preparation_failure_returns_safe_error() -> None:
    module = StubAttackModule(error=RuntimeError("do-not-expose"))

    result = Runner(
        attack_module_registry=make_registry(module),
    ).run(
        make_testcase(),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Attack module preparation failed."
    assert "do-not-expose" not in result.reason


def test_failed_execution_continues_through_observer_and_evaluator() -> None:
    prepared_input = CoreTestInput(id="input-prepared", prompt="prepared")
    execution = ExecutionResult(
        success=False,
        status_code=None,
        error="connection refused",
    )
    observer = RecordingResponseObserver()
    evaluator = RecordingResponseEvaluator()

    result = Runner(
        executor=StubExecutor(result=execution),
        observer=observer,
        evaluator=evaluator,
        attack_module_registry=make_registry(
            StubAttackModule(prepared_input=prepared_input)
        ),
    ).run(
        make_testcase(),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert "connection refused" in result.reason
    assert observer.calls == [execution]
    assert len(evaluator.calls) == 1
    assert evaluator.calls[0][1].metadata["execution_success"] is False


def test_unexpected_executor_exception_returns_safe_execution_error() -> None:
    result = Runner(
        executor=StubExecutor(error=RuntimeError("do-not-expose")),
        attack_module_registry=make_registry(
            StubAttackModule(
                prepared_input=CoreTestInput(id="prepared", prompt="test")
            )
        ),
    ).run(
        make_testcase(),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Execution stage failed."
    assert "do-not-expose" not in result.reason


def test_observer_exception_returns_safe_observation_error() -> None:
    result = Runner(
        executor=StubExecutor(result=ExecutionResult(success=True)),
        observer=StubObserver(error=RuntimeError("do-not-expose")),
        attack_module_registry=make_registry(
            StubAttackModule(
                prepared_input=CoreTestInput(id="prepared", prompt="test")
            )
        ),
    ).run(
        make_testcase(),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Observation stage failed."
    assert "do-not-expose" not in result.reason


def test_evaluator_exception_returns_safe_evaluation_error() -> None:
    observation = Observation(
        response_text="response",
        metadata={"execution_success": True},
    )
    result = Runner(
        executor=StubExecutor(result=ExecutionResult(success=True)),
        observer=StubObserver(observation=observation),
        evaluator=StubEvaluator(error=RuntimeError("do-not-expose")),
        attack_module_registry=make_registry(
            StubAttackModule(
                prepared_input=CoreTestInput(id="prepared", prompt="test")
            )
        ),
    ).run(
        make_testcase(),
        make_target(),
        CoreTestInput(id="input-001", prompt="test"),
    )

    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Evaluation stage failed."
    assert "do-not-expose" not in result.reason
