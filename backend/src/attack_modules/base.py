from abc import ABC, abstractmethod

from core.models import TestCase, TestInput

class BaseAttackModule(ABC):
    @abstractmethod
    def prepare(
        self,
        testcase: TestCase,
        test_input: TestInput
    ) -> TestInput:
        pass
