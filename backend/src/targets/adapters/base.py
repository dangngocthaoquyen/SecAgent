"""Base abstraction for target adapters."""

from abc import ABC, abstractmethod

from core.models import ExecutionResult, TargetProfile, TestInput


class BaseTargetAdapter(ABC):
    """Translate target-agnostic test input into one target execution."""

    @abstractmethod
    def execute(
        self,
        target: TargetProfile,
        test_input: TestInput,
    ) -> ExecutionResult:
        """Execute a test input against a target profile."""
