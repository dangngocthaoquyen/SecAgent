from abc import ABC, abstractmethod

from src.core.models.evaluation import EvaluationResult
from src.core.models.observation import Observation
from src.core.models.testcase import TestCase

class BaseEvaluator(ABC):
    @abstractmethod
    def evaluate(
        self,
        testcase: TestCase,
        observation: Observation
    ) -> EvaluationResult:
        pass