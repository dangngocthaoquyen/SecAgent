"""Run one testcase through preparation, execution, observation, and evaluation."""

from attack_modules import (
    AttackModuleRegistry,
    AttackModuleRegistryError,
    build_default_attack_module_registry,
)
from core.models import (
    EvaluationResult,
    EvaluationStatus,
    TargetProfile,
    TestCase,
    TestInput,
)
from evaluators import BaseEvaluator, ResponseEvaluator
from observers import BaseObserver, ResponseObserver
from testing.executor import Executor

class  Runner:
    def __init__(
        self,
        executor: Executor | None = None,
        observer: BaseObserver | None = None,
        evaluator: BaseEvaluator | None = None,
        attack_module_registry: AttackModuleRegistry | None = None,
    ) -> None:
        self._executor = executor if executor is not None else Executor()
        self._observer = observer if observer is not None else ResponseObserver()
        self._evaluator = evaluator if evaluator is not None else ResponseEvaluator()
        self._attack_module_registry = (
            attack_module_registry
            if attack_module_registry is not None
            else build_default_attack_module_registry()
        )

    def run(
        self,
        testcase: TestCase,
        target: TargetProfile,
        test_input: TestInput,
    ) -> EvaluationResult:
        try:
           attack_module = self._attack_module_registry.resolve(testcase.attack_module)
        except AttackModuleRegistryError as exc:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason=f"Attack module resolution failed: {exc}",
            )

        try:
            prepared_input = attack_module.prepare(testcase, test_input)
        except ValueError as exc:
            return EvaluationResult(
                status=EvaluationStatus.ERROR,
                reason=f"Attack module preparation failed: {exc}",
            )

        execution_result = self._executor.execute(target, prepared_input)
        observation = self._observer.observe(execution_result)

        return self._evaluator.evaluate(testcase, observation)