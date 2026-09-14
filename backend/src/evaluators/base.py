from abc import ABC, abstractmethod

from core.models import EvaluationResult, Observation, TestCase

class BaseEvaluator(ABC):
    @abstractmethod
    def evaluate(
        self,
        testcase: TestCase,
        observation: Observation
    ) -> EvaluationResult:
        pass
