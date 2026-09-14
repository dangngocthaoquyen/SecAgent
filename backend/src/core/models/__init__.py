"""Public exports for the core Pydantic models."""

from core.models.execution import ExecutionResult
from core.models.observation import Observation
from core.models.target import TargetInterface, TargetProfile
from core.models.test_input import TestInput

__all__ = [
    "ExecutionResult",
    "Observation",
    "TargetInterface",
    "TargetProfile",
    "TestInput",
]

