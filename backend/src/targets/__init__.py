"""Target configuration loading and validation."""

from targets.loader import TargetLoadError, load_target
from targets.validator import TargetValidationError, validate_target

__all__ = [
    "TargetLoadError",
    "TargetValidationError",
    "load_target",
    "validate_target",
]
