"""Base abstraction for execution result observers."""

from abc import ABC, abstractmethod

from core.models import ExecutionResult, Observation


class BaseObserver(ABC):
    """Normalize execution results for downstream consumers."""

    @abstractmethod
    def observe(self, result: ExecutionResult) -> Observation:
        """Convert an execution result into an observation."""
