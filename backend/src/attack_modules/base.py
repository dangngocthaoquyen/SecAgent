from abc import ABC, abstractmethod

from src.core.models.testcase import TestCase
from src.core.models.test_input import TestInput

class BaseAttackModule(ABC):
    @abstractmethod
    def prepare(
        self,
        testcase: TestCase,
        test_input: TestInput
    ) -> TestInput:
        pass